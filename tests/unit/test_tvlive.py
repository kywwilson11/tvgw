"""(app in front) The live reading's connection discipline (design decision 67), without a TV: the rules
one by one, the service's own loop run for simulated days against TVs that flap, hang, forget the key or
sit switched off with their link up, and one session at a time against a fake SSAP server on localhost
(test_tvprobe.FakeTv). LG locks a TV out after too many pairing requests, so what is proved here is what
the service does NOT send."""

import asyncio
import dataclasses
import json
import os
import socket
import tempfile
import time
from datetime import datetime

import pytest
from conftest import ROOT, UNITS, counting_lgtv, fake_lgtv
from test_tvprobe import Conn, FakeTv, run

from tvgw import appeval, appfront, cli, config, db, forget, ingest, lgkeys, lgwebos, tvlive
from tvgw.tvlive import (
    CONFLICT,
    FAILED,
    HOURLY,
    LOST,
    REFUSED,
    SERVICE,
    STANDBY,
    STOPPED,
    UNSUPPORTED,
    Discipline,
    Ledger,
    Rules,
    Seen,
    Traffic,
)

T0 = 1_800_000_000.0  # some moment; the simulations count from here
TV = "10.10.10.17"


# ---- the attempts file --------------------------------------------------------------------------------
def test_the_ledger_keeps_the_last_hour_whoever_wrote_it(tmp_path):
    led = Ledger(str(tmp_path / "attempts"))
    led.note(SERVICE, T0)
    led.note(HOURLY, T0 + 100)
    led.note(SERVICE, T0 + 3599)
    assert led.recent(T0 + 3599) == [(T0, SERVICE), (T0 + 100, HOURLY), (T0 + 3599, SERVICE)]
    assert led.recent(T0 + 3600) == [(T0 + 100, HOURLY), (T0 + 3599, SERVICE)]  # an hour is an hour
    assert oct(os.stat(led.path).st_mode & 0o777) == "0o600"


def test_a_line_nobody_can_read_or_a_time_ahead_of_the_clock_counts_as_an_attempt_made_now(tmp_path):
    """A damaged file, or a clock set back, can only make the service more careful."""
    path = tmp_path / "attempts"
    path.write_text(f"garbage\n{T0 + 9000:.3f} live\n\n{T0 - 10:.3f}\nnan live\n", encoding="utf-8")
    assert Ledger(str(path)).recent(T0) == [(T0, "?"), (T0, "live"), (T0 - 10, "?"), (T0, "live")]


def test_the_ledger_is_cut_back_to_the_last_hour_when_it_grows(tmp_path):
    led = Ledger(str(tmp_path / "attempts"))
    for i in range(1200):
        led.note(SERVICE, T0 + i * 10)  # 12,000 seconds of attempts, far more than the file's limit
    assert os.path.getsize(led.path) < 17_000
    recent = led.recent(T0 + 11_990)
    assert len(recent) == 360 and recent[0][0] == T0 + 8400  # nothing of the last hour was lost


def test_a_missing_ledger_cannot_be_read_and_a_directory_cannot_be_written(tmp_path):
    with pytest.raises(OSError):
        Ledger(str(tmp_path / "none")).recent(T0)
    with pytest.raises(OSError):
        Ledger(str(tmp_path)).note(SERVICE, T0)


def test_the_hourly_reading_counts_its_attempts_only_where_the_service_has_run(tmp_path):
    """With the default settings the file is never made, and the reading writes nothing new anywhere."""
    key_file = str(tmp_path / "lgtv-keys.sqlite")
    tvlive.note_attempt(key_file, now=T0)
    assert os.listdir(tmp_path) == []
    led = Ledger(tvlive.state_path(key_file, tvlive.ATTEMPTS_FILE))
    led.create()
    tvlive.note_attempt(key_file, now=T0)
    assert led.recent(T0) == [(T0, HOURLY)]
    os.chmod(led.path, 0o400)
    os.unlink(led.path)
    os.mkdir(led.path)  # a path that cannot be opened for writing: the reading must not fail on it
    tvlive.note_attempt(key_file, now=T0)


# ---- evidence from the TV port --------------------------------------------------------------------------
def test_traffic_is_evidence_once_the_counter_moved_enough_inside_the_window():
    tr = Traffic(need=8_000, seconds=30.0)
    tr.reset(0.0, 1_000)
    for t in range(2, 20, 2):
        tr.sample(t, 1_000 + t * 100)  # 50 bytes a second: an idle link's chatter
        assert not tr.seen(t)
    tr.sample(20.0, 9_900)
    assert tr.seen(20.0)  # 8,900 bytes since the reset, inside 30 s
    tr.reset(20.0, 9_900)
    assert not tr.seen(20.0)  # what the port carried up to an attempt is not evidence for the next
    for t in range(22, 120, 2):
        tr.sample(t, 9_900 + (t - 20) * 100)
    assert not tr.seen(118.0)  # 9,800 bytes, but over 98 s: never 8,000 inside 30


def test_traffic_that_stopped_is_not_evidence_and_a_counter_that_restarts_or_cannot_be_read_starts_over():
    tr = Traffic(need=8_000, seconds=30.0)
    tr.reset(0.0, 0)
    tr.sample(2.0, 50_000)
    assert tr.seen(2.0) and tr.seen(30.0) and not tr.seen(40.0)  # the newest sample is too old
    tr.sample(42.0, 10)  # the counter went down: the interface came back
    assert not tr.seen(42.0)
    tr.sample(44.0, 9_000)
    assert tr.seen(44.0)
    tr.sample(46.0, None)
    assert not tr.seen(46.0) and not tr.readable
    tr.sample(48.0, 99_000)
    assert not tr.seen(48.0)  # one sample is no movement


def test_a_pause_in_the_sampling_is_not_a_window():
    tr = Traffic(need=8_000, seconds=30.0)
    tr.reset(0.0, 0)
    tr.sample(500.0, 50_000)  # nobody looked for 500 s: this says nothing about the last 30
    assert not tr.seen(500.0)


# ---- the rules, one by one ------------------------------------------------------------------------------
@pytest.fixture
def rule(tmp_path):
    led = Ledger(str(tmp_path / "attempts"))
    led.create()
    return Discipline(led)


def seen(now=T0, **kw):
    base = dict(
        key=True, refused=False, stood_down=None, carrier=True, traffic=True, reading=None, mono=now - T0
    )
    return Seen(now, **{**base, **kw})


def test_every_condition_holds_and_the_service_may_try(rule):
    assert rule.why_not(seen()) is None
    assert rule.why_not(seen(carrier=None)) is None  # a kernel that does not say is not a link down


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"stood_down": "2026-11-05 20:20 the hourly reading could not reach the TV"}, "stood down: 2026"),
        ({"key": False}, "not paired"),
        ({"refused": True}, "the TV refused the key"),
        ({"carrier": False}, "no link on the TV port"),
        ({"traffic": False}, "no sign that the TV is on"),
    ],
)
def test_one_condition_that_does_not_hold_is_enough(rule, change, why):
    assert rule.why_not(seen(**change)).startswith(why)


def test_a_carrier_that_is_up_is_no_evidence_at_all(rule):
    """The reference CX keeps its link up while it is off: 35 readings off, not one carrier loss."""
    assert rule.why_not(seen(carrier=True, traffic=False)) == "no sign that the TV is on"


def test_an_hourly_reading_that_found_the_tv_awake_is_evidence_once(rule):
    quiet = dict(traffic=False)
    assert rule.why_not(seen(reading=(T0 - 60, "Active"), **quiet)) is None
    assert rule.why_not(seen(reading=(T0 - 60, "Screen Saver"), **quiet)) is None
    assert rule.why_not(seen(reading=(T0 - 60, "unreachable"), **quiet)) == "no sign that the TV is on"
    assert rule.why_not(seen(reading=(T0 - 60, "unknown"), **quiet)) == "no sign that the TV is on"
    assert rule.why_not(seen(reading=(T0 - 4300, "Active"), **quiet)) == "no sign that the TV is on"  # stale
    assert rule.why_not(seen(reading=(T0 + 90, "Active"), **quiet)) == "no sign that the TV is on"  # ahead
    # the same reading is not evidence for a second attempt
    assert rule.begin(T0)
    rule.end(T0 + 5, FAILED, 0.0)
    later = T0 + 2000
    assert rule.why_not(seen(later, reading=(T0 - 60, "Active"), **quiet)) == "no sign that the TV is on"
    assert rule.why_not(seen(later, reading=(T0 + 1900, "Active"), **quiet)) is None


def test_the_back_off_grows_with_each_failure_and_never_goes_under_the_gap(rule):
    r = rule.rules
    now = T0
    waits = []
    for _ in range(9):
        assert rule.begin(now, now - T0)
        rule.end(now, FAILED, 0.0)
        fresh = (now + 1, "Active")  # a reading after each failure, so evidence is never what is missing
        wait = next(
            w
            for w in range(5, 2000, 5)
            if rule.why_not(seen(now + w, reading=fresh, mono=now + w - T0)) != "backing off"
        )
        waits.append(wait)
        now += 4000  # an hour and more on: the hour's count is never what is missing either
    assert waits == [15, 30, 60, 120, 300, 600, 900, 900, 900] and r.backoff[-1] == 900


def test_a_session_that_was_lost_at_once_waits_the_gap_and_one_that_held_clears_the_failures(rule):
    for _ in range(4):
        rule.begin(T0)
        rule.end(T0, LOST, 20.0)  # up 20 s and gone: a flap
    assert rule.failures == 4
    rule.begin(T0 + 5000)
    rule.end(T0 + 9000, LOST, 4000.0)  # an evening's session, lost at its end
    assert rule.failures == 0
    assert rule.why_not(seen(T0 + 9010)) == "backing off"  # the gap after anything
    assert rule.why_not(seen(T0 + 9015)) is None


def test_after_a_few_failures_in_a_row_traffic_alone_is_no_longer_evidence(rule):
    """A TV whose traffic says on while its API does not answer: from the third failure only a reading
    that reached the TV counts, and that is one attempt an hour at most."""
    now = T0
    for _ in range(3):
        assert rule.why_not(seen(now, mono=now - T0)) is None
        rule.begin(now, now - T0)
        rule.end(now + 15, FAILED, 0.0)
        now += 1000
    assert rule.why_not(seen(now, mono=now - T0)) == "no sign that the TV is on"
    assert rule.why_not(seen(now, mono=now - T0, reading=(now - 30, "Active"))) is None


def test_the_tv_saying_it_switches_off_holds_the_next_attempt_back(rule):
    rule.begin(T0)
    rule.end(T0 + 3600, STANDBY, 3600.0)
    assert rule.why_not(seen(T0 + 3600 + 60)) == "holding off after the TV switched off"
    assert rule.why_not(seen(T0 + 3600 + 120)) is None
    assert rule.failures == 0
    # a TV found already in standby: the evidence was wrong, and that is a failure
    rule.begin(T0 + 4000)
    rule.end(T0 + 4002, STANDBY, 2.0)
    assert rule.failures == 1


@pytest.mark.parametrize("outcome", [REFUSED, STOPPED, CONFLICT, UNSUPPORTED])
def test_an_ending_that_is_not_the_tvs_fault_is_no_failure(rule, outcome):
    rule.begin(T0)
    rule.end(T0 + 30, outcome, 30.0)
    assert rule.failures == 0


def test_the_hour_has_room_for_six_attempts_by_anyone(rule):
    for i in range(4):
        rule.ledger.note(SERVICE, T0 + i)
    rule.ledger.note(HOURLY, T0 - 1000)
    assert rule.why_not(seen(T0 + 10)) is None  # five in the hour
    rule.ledger.note(HOURLY, T0 - 999)
    assert rule.why_not(seen(T0 + 10)) == "the hour's attempts are used"
    assert rule.why_not(seen(T0 + 2601)) is None  # the reading's first attempt is an hour old
    assert tvlive.SERVICE_LIMIT + tvlive.RESERVED == tvlive.CEILING == 8


def test_no_attempt_while_the_hourly_reading_is_at_work(rule):
    rule.ledger.note(HOURLY, T0 - 30)
    assert rule.why_not(seen()) == "the hourly reading is at work"
    assert rule.why_not(seen(T0 + 90)) is None
    rule.ledger.note(SERVICE, T0 + 100)
    assert rule.why_not(seen(T0 + 101)) is None  # its own attempts are the back-off's business


def test_an_attempts_file_that_cannot_be_read_or_written_means_no_attempt(rule):
    os.unlink(rule.ledger.path)
    assert rule.why_not(seen()) == "the attempts file cannot be read"
    os.mkdir(rule.ledger.path)
    assert rule.begin(T0) is False and rule.attempts == 0


def test_setting_the_clock_forward_does_not_empty_the_hour(rule):
    """The file counts by the wall clock, which can be set; the process counts by the steady one too."""
    for i in range(6):
        assert rule.begin(T0 + i, mono=float(i))
    jumped = T0 + 2 * 86400  # the clock set two days forward, ten steady seconds later
    assert rule.ledger.recent(jumped) == []
    assert rule.why_not(seen(jumped, mono=10.0)) == "the hour's attempts are used"
    assert rule.why_not(seen(jumped + 3600, mono=3606.0)) is None


# ---- the service's loop, for simulated days ---------------------------------------------------------------
class Sim:
    """A gateway and a TV in fast time: `sleep` moves the clocks, the port's counter runs at `rx_rate`
    bytes a second, the hourly reading happens at 20 past (two attempts in the file, a line of history),
    and each attempt the service makes is answered by `tv(sim)` with (outcome, seconds up, seconds taken)."""

    def __init__(self, tmp_path, tv, hours=24.0, rx_rate=2_000, power=lambda t: "Active", rules=None):
        self.t, self.steady = T0, 1000.0
        self.until = T0 + hours * 3600
        self.tv, self.rx_rate, self.power = tv, rx_rate, power
        self.rx = 0.0
        self.rules = rules or Rules()
        self.ledger = Ledger(str(tmp_path / "attempts"))
        self.ledger.create()
        self.log = tvlive.EventLog(str(tmp_path / "events.log"), clock=lambda: self.t)
        self.key: str | None = "stored-key"
        self.rec = lgkeys.Pairing(TV)
        self.marker: str | None = None
        self.history: tuple[float, str] | None = None
        self.tries: list[float] = []
        self.readings = 0
        self.next_reading = T0 + 1200

    def advance(self, seconds: float) -> None:
        end = self.t + seconds
        while self.next_reading <= end:  # the hourly reading: counted, never refused
            if self.key and not self.rec.refused:
                self.ledger.note(HOURLY, self.next_reading - 20)
                self.ledger.note(HOURLY, self.next_reading - 15)
                self.history = (self.next_reading, self.power(self.next_reading))
                self.readings += 1
            self.next_reading += 3600
        self.rx += self.rate() * seconds
        self.steady += seconds
        self.t = end

    def rate(self) -> float:
        return self.rx_rate(self.t) if callable(self.rx_rate) else self.rx_rate

    async def sleep(self, seconds: float) -> None:
        self.advance(seconds)

    async def session(self, env, rules, log, key, manifest):
        assert key == "stored-key" and self.key and not self.rec.refused and self.marker is None
        self.tries.append(self.t)
        outcome, up, took = self.tv(self)
        self.advance(took)
        return outcome, up

    def refuse(self, why: str) -> None:
        self.rec = dataclasses.replace(self.rec, refused_at=self.t, refused_why=why)

    def stand_down(self, why: str) -> None:
        self.marker = why

    async def stored_key(self):
        return self.key

    def env(self) -> tvlive.Env:
        return tvlive.Env(
            connect=None,
            key=self.stored_key,
            record=lambda: self.rec,
            manifest=lambda kind: {"kind": kind},
            refuse=self.refuse,
            rx_bytes=lambda: int(self.rx),
            carrier=lambda: True,  # as on the reference CX: up whether the TV is on or off
            reading=lambda: self.history,
            stood_down=lambda: self.marker,
            stand_down=self.stand_down,
            clock=lambda: self.t,
            mono=lambda: self.steady,
            sleep=self.sleep,
            stopping=lambda: self.t >= self.until,
            session=self.session,
        )

    def go(self) -> "Sim":
        assert asyncio.run(tvlive.run(self.env(), self.ledger, self.log, self.rules)) == 0
        self.log.close()
        return self

    def busiest_hour(self) -> int:
        """The most attempts by anyone in any 3600 s: the service's and the hourly reading's."""
        return appeval.busiest_hour(
            self.tries + [self.readings_at(i) + d for i in range(self.readings) for d in (0, 5)]
        )

    @staticmethod
    def readings_at(i: int) -> float:
        return T0 + 1180 + 3600 * i


def flapping(sim):
    return LOST, 20.0, 25.0  # up for 20 s, then gone, again and again


def hanging(sim):
    return FAILED, 0.0, 15.0  # accepts the connection and never answers the registration


def test_a_flapping_tv_never_gets_more_than_the_hours_attempts(tmp_path):
    sim = Sim(tmp_path, flapping, hours=48).go()
    assert appeval.busiest_hour(sim.tries) <= tvlive.SERVICE_LIMIT
    assert sim.busiest_hour() <= tvlive.CEILING
    # three tries on the port's traffic, then one after each hourly reading that found the TV awake,
    # and after twelve failures in a row it stops knocking until the owner has looked
    assert len(sim.tries) == tvlive.GIVE_UP == 12 and sim.readings == 48
    assert sim.marker == "12 attempts in a row failed"
    assert all(abs(b - a - 3600) <= 2 for a, b in zip(sim.tries[3:], sim.tries[4:], strict=False))


def test_a_flapping_tv_with_every_other_rule_out_of_the_way_is_stopped_by_the_ceiling_alone(tmp_path):
    """Back-off and the evidence rule set aside: the file's count is still a wall."""
    loose = Rules(backoff=(0.0,), min_gap=0.0, traffic_trusted=10**9, yield_s=0.0, give_up=10**9)
    sim = Sim(tmp_path, flapping, hours=12, rules=loose).go()
    assert sim.busiest_hour() <= tvlive.CEILING and appeval.busiest_hour(sim.tries) <= tvlive.SERVICE_LIMIT
    assert len(sim.tries) > 40  # it did try as often as the ceiling let it


def test_a_tv_that_accepts_and_then_hangs_is_tried_three_times_and_then_only_after_a_reading(tmp_path):
    sim = Sim(tmp_path, hanging, hours=24, power=lambda t: "unreachable").go()
    assert len(sim.tries) == 3  # the readings never reached the TV either: nothing more, all day
    sim = Sim(tmp_path / "..", hanging, hours=24).go()
    assert appeval.busiest_hour(sim.tries) <= tvlive.SERVICE_LIMIT and sim.busiest_hour() <= tvlive.CEILING
    assert len(sim.tries) == 12 and sim.marker == "12 attempts in a row failed"


def test_a_key_the_tv_has_forgotten_is_sent_once_and_never_again(tmp_path):
    def forgot(sim):
        sim.refuse("the TV asked for a new pairing (a prompt on the screen)")
        return REFUSED, 0.0, 3.0

    sim = Sim(tmp_path, forgot, hours=72).go()
    assert len(sim.tries) == 1
    assert sim.readings == 0  # and the hourly reading obeys the same record
    with open(tmp_path / "events.log", encoding="utf-8") as fh:
        kinds = [json.loads(line)["kind"] for line in fh]
    assert kinds == ["watch.start", "watch.idle", "watch.stop"]


def test_a_tv_that_is_off_with_its_link_up_is_never_tried(tmp_path):
    """The night on the reference: carrier up, nothing from the TV, readings that find it unreachable."""
    sim = Sim(tmp_path, hanging, hours=24, rx_rate=0, power=lambda t: "unreachable").go()
    assert sim.tries == [] and sim.readings == 24


def test_a_trickle_from_a_sleeping_tv_is_not_evidence(tmp_path):
    sim = Sim(tmp_path, hanging, hours=24, rx_rate=100, power=lambda t: "unreachable").go()  # 3 KB in 30 s
    assert sim.tries == []


def test_an_evening_is_one_attempt_and_the_next_evening_one_more(tmp_path):
    """The TV comes on at 19:00 and goes off at 23:00, two days running: the service connects when the
    traffic starts, holds the session, lets go when the TV says it is switching off, and is silent all
    night."""

    def evening_tv(sim):
        hour = ((sim.t - T0) / 3600) % 24
        return STANDBY, (23 - hour) * 3600, (23 - hour) * 3600

    def on(t):
        return 19 <= ((t - T0) / 3600) % 24 < 23

    sim = Sim(tmp_path, evening_tv, hours=48, rx_rate=lambda t: 5_000 if on(t) else 0)
    sim.power = lambda t: "Active" if on(t) else "unreachable"
    sim.go()
    assert len(sim.tries) == 2
    assert [round(((t - T0) / 3600) % 24, 2) for t in sim.tries] == [19.0, 19.0]  # within a tick or two


def test_a_tv_still_talking_in_standby_is_asked_again_ever_more_slowly(tmp_path):
    """Active Standby with the network up: every attempt finds the TV saying it is off. Each such find is
    a failure, so after three the traffic is no longer believed."""
    sim = Sim(tmp_path, lambda sim: (STANDBY, 1.0, 2.0), hours=24, power=lambda t: "unreachable").go()
    assert len(sim.tries) == 3 and sim.tries[1] - sim.tries[0] >= tvlive.STANDBY_HOLD


def test_a_tv_that_chatters_into_standby_is_still_met_at_once_the_next_evening(tmp_path):
    """On from 19:00 to 23:00, then eight minutes of traffic while it answers "standby", then silence. The
    failures of those minutes must not make the service wait for an hourly reading the next evening: the
    silence of the night ends that count."""

    def hour(t):
        return ((t - T0) / 3600) % 24

    def tv(sim):
        h = hour(sim.t)
        if 19 <= h < 23:
            return STANDBY, (23 - h) * 3600, (23 - h) * 3600
        return (STANDBY, 1.0, 2.0) if 23 <= h < 23.14 else (FAILED, 0.0, 5.0)

    sim = Sim(tmp_path, tv, hours=72, rx_rate=lambda t: 5_000 if 19 <= hour(t) < 23.14 else 0)
    sim.power = lambda t: "Active" if 19 <= hour(t) < 23 else "unreachable"
    sim.go()
    evenings = [t for t in sim.tries if 18.99 <= hour(t) < 19.05]
    assert len(evenings) == 3  # each evening met within a tick or two of its first traffic
    assert 3 <= len(sim.tries) <= 3 * 4 and sim.marker is None  # and at most three knocks into each standby
    assert appeval.busiest_hour(sim.tries) <= tvlive.SERVICE_LIMIT


def test_silence_ends_the_count_of_failures_in_a_row_but_not_the_count_that_gives_up(rule):
    for i in range(3):
        rule.begin(T0 + 100 * i, float(100 * i))
        rule.end(T0 + 100 * i + 5, FAILED, 0.0)
    late = T0 + 5000
    assert rule.why_not(seen(late, mono=5000.0)) == "no sign that the TV is on"  # traffic is not believed
    assert rule.why_not(seen(late, mono=5000.0, quiet=599.0)) == "no sign that the TV is on"
    assert rule.why_not(seen(late, mono=5000.0, quiet=600.0, traffic=False)) == "no sign that the TV is on"
    assert (rule.failures, rule.unanswered) == (0, 3)  # the night's silence forgave the row, not the total
    assert rule.why_not(seen(late + 10, mono=5010.0)) is None  # the next traffic is believed again
    rule.begin(late + 10, 5010.0)
    rule.end(late + 4000, STANDBY, 3990.0)  # an evening's session
    assert (rule.failures, rule.unanswered) == (0, 0)


def test_a_tv_whose_api_fails_every_evening_is_given_up_on_whatever_the_nights_forgive(tmp_path):
    def hour(t):
        return ((t - T0) / 3600) % 24

    sim = Sim(tmp_path, hanging, hours=24 * 8, rx_rate=lambda t: 5_000 if 19 <= hour(t) < 23 else 0)
    sim.power = lambda t: "unreachable"
    sim.go()
    assert (
        len(sim.tries) == tvlive.GIVE_UP and sim.marker == "12 attempts in a row failed"
    )  # three an evening


def test_a_service_that_crashes_and_restarts_all_hour_is_held_by_the_file(tmp_path):
    """systemd starts a crashed service again after a minute; each new process knows nothing but the
    file."""
    tries = []
    for i in range(40):  # forty lives of 90 s
        sim = Sim(tmp_path, flapping, hours=0.025)
        sim.t = T0 + i * 90.0
        sim.until = sim.t + 90.0
        sim.next_reading = T0 + 10**9
        sim.go()
        tries += sim.tries
    assert len(tries) >= 6 and appeval.busiest_hour(tries) <= tvlive.SERVICE_LIMIT


def test_a_service_that_has_stood_down_tries_nothing_until_the_owner_says(tmp_path):
    sim = Sim(tmp_path, flapping, hours=24)
    sim.marker = "2026-11-05 20:21 the hourly reading could not reach the TV while the live reading held it"
    sim.go()
    assert sim.tries == []


def test_a_tv_that_refuses_a_subscription_makes_the_service_stand_down(tmp_path):
    sim = Sim(tmp_path, lambda sim: (UNSUPPORTED, 2.0, 2.0), hours=24).go()
    assert len(sim.tries) == 1 and "subscription" in sim.marker


def test_no_key_means_no_attempt_and_a_pairing_made_later_is_found(tmp_path):
    sim = Sim(tmp_path, lambda sim: (STANDBY, 3000.0, 3000.0), hours=1.5)
    sim.key = None
    sim.power = lambda t: "unknown"
    real_advance = sim.advance

    def advance(seconds):
        real_advance(seconds)
        if sim.t >= T0 + 3600:
            sim.key = "stored-key"  # sudo tvgw tv pair, an hour in

    sim.advance = advance
    sim.go()
    assert len(sim.tries) == 1 and T0 + 3600 <= sim.tries[0] <= T0 + 3600 + tvlive.KEY_RECHECK + 5


def test_a_refusal_the_hourly_reading_recorded_a_moment_ago_stops_the_attempt(tmp_path):
    """The key store is read again just before every attempt, not once a minute."""
    sim = Sim(tmp_path, flapping, hours=1, rx_rate=0)
    real_advance = sim.advance

    def advance(seconds):
        real_advance(seconds)
        if sim.t >= T0 + 1000 and not sim.rec.refused:
            sim.refuse("403 blacklisted")  # the hourly reading was refused...
            sim.rx_rate = 5_000  # ...and at that moment the traffic says the TV is on

    sim.advance = advance
    sim.go()
    assert sim.tries == []


def test_an_attempts_file_that_cannot_be_written_means_no_attempt_in_the_loop(tmp_path):
    sim = Sim(tmp_path, flapping, hours=2)
    sim.next_reading = T0 + 10**9
    os.unlink(sim.ledger.path)
    os.mkdir(sim.ledger.path)
    sim.go()
    assert sim.tries == []


# ---- one session, against a fake TV on localhost ---------------------------------------------------------
FAST = Rules(
    io_timeout=1.0, connect_timeout=1.0, register_grace=0.2, ping=0.15, pong_timeout=0.3, alive_every=0.2
)
REGISTERED = {"type": "registered", "id": "register_0", "payload": {"client-key": "stored-key"}}


def push(sid, **payload):
    return {"type": "response", "id": sid, "payload": {"returnValue": True, **payload}}


async def serve(conn: Conn, pushes=(), then=None) -> None:
    reg = await conn.recv()
    assert reg["type"] == "register" and reg["payload"]["client-key"] == "stored-key"
    assert reg["payload"]["forcePairing"] is False
    await conn.send(REGISTERED)
    for _ in range(2):
        sub = await conn.recv()
        assert sub["type"] == "subscribe"
    for p in pushes:
        await conn.send(p)
    if then is not None:
        await then(conn)
    await conn.drain_until_close()


class Bench:
    """One `held()` call against a FakeTv, with the things it may touch recorded."""

    def __init__(self, tmp_path, script, rules=FAST):
        self.tmp_path, self.script, self.rules = tmp_path, script, rules
        self.refused: list[str] = []
        self.stood_down: list[str] = []
        self.history = None
        self.stop = False
        self.wall_ahead = 0.0
        self.tv: FakeTv | None = None

    def env(self, port: int) -> tvlive.Env:
        async def connect():
            return await lgwebos._WebSocket.connect(
                "127.0.0.1", port, None, timeout=self.rules.connect_timeout
            )

        async def key():
            return "stored-key"

        loop = asyncio.get_running_loop()
        return tvlive.Env(
            connect=connect,
            key=key,
            record=lambda: lgkeys.Pairing(TV),
            manifest=lambda kind: {"permissions": ["READ_POWER_STATE"]},
            refuse=self.refused.append,
            rx_bytes=lambda: 0,
            carrier=lambda: True,
            reading=lambda: self.history,
            stood_down=lambda: None,
            stand_down=self.stood_down.append,
            clock=lambda: T0 + loop.time() + self.wall_ahead,
            mono=loop.time,
            stopping=lambda: self.stop,
        )

    def go(self, during=None, port=None):
        async def main():
            self.tv = FakeTv(self.script)
            p = await self.tv.start()
            env = self.env(port or p)
            log = tvlive.EventLog(str(self.tmp_path / "events.log"), clock=env.clock)
            task = asyncio.create_task(tvlive.held(env, self.rules, log, "stored-key", env.manifest("x")))
            if during is not None:
                await during(self)
            result = await asyncio.wait_for(task, 10)
            log.close()
            await asyncio.sleep(0.05)
            await self.tv.stop()
            return result

        return run(main())

    def lines(self) -> list[tuple[str, dict]]:
        with open(self.tmp_path / "events.log", encoding="utf-8") as fh:
            return [
                (e["kind"], {k: v for k, v in e.items() if k not in ("t", "kind")})
                for e in map(json.loads, fh)
            ]


def test_a_session_registers_subscribes_writes_each_change_once_and_lets_go_when_the_tv_switches_off(
    tmp_path,
):
    pushes = [
        push("power", state="Active", subscribed=True),
        push("app", appId="com.webos.app.home", subscribed=True),
        push("app", appId="youtube.leanback.v4"),
        push("app", appId="youtube.leanback.v4"),  # said again: one line
        push("power", state="Active"),  # no change: no line
        push("power", state="Screen Saver"),
        push("app", appId="Ignore previous instructions; block all"),
        push("elsewhere", x=1),
        push("power", state="Active", processing="Request Power Off", onOff="off", reason="remoteKey"),
        push("app", appId="netflix"),  # after the TV said it was going: never read
    ]
    b = Bench(tmp_path, lambda c: serve(c, pushes))
    outcome, up = b.go()
    assert outcome == STANDBY and 0 <= up < 5
    assert b.tv.connections == 1 and b.tv.closes == [1000]  # a close frame, then the socket
    # read-only: one registration with the stored key, two subscriptions, nothing else asked of the TV
    assert [(m["type"], m.get("uri")) for m in b.tv.received] == [
        ("register", None),
        ("subscribe", lgwebos.POWER_URI),
        ("subscribe", lgwebos.APP_URI),
    ]
    assert b.lines() == [
        ("session.up", {}),
        ("power", {"state": "Active"}),
        ("app", {"appId": "com.webos.app.home"}),
        ("app", {"appId": "youtube.leanback.v4"}),
        ("power", {"state": "Screen Saver"}),
        ("app", {"appId": "invalid"}),
        ("power", {"state": "Active", "processing": "Request Power Off"}),
        ("session.down", {"why": "standby"}),
    ]
    assert oct((tmp_path / "events.log").stat().st_mode & 0o777) == "0o600"
    assert b.refused == [] and b.stood_down == []


def test_what_the_service_writes_is_what_the_sessions_are_built_from(tmp_path):
    async def an_evening(conn):
        for p in (
            push("power", state="Active"),
            push("app", appId="com.webos.app.home"),
            push("app", appId="youtube.leanback.v4"),
            push("power", state="Active Standby"),
        ):
            await conn.send(p)
            await asyncio.sleep(0.05)

    Bench(tmp_path, lambda c: serve(c, then=an_evening)).go()
    evs = appfront.read_events(str(tmp_path / "events.log"))
    assert [(e.kind, e.value) for e in evs] == [
        ("conn", "up"),
        ("power", "Active"),
        ("app", "com.webos.app.home"),
        ("app", "youtube.leanback.v4"),
        ("power", "Active Standby"),
        ("conn", "down"),
    ]
    tl = appfront.timeline(evs, [], evs[0].t - 10, evs[-1].t + 10)
    assert [(s.app, s.end_why) for s in tl.sessions] == [
        ("com.webos.app.home", "app"),
        ("youtube.leanback.v4", "off"),
    ]


@pytest.mark.parametrize(
    "answer",
    [
        [
            {
                "type": "error",
                "id": "register_0",
                "error": "403 Pairing rejected: blacklisted certificate detected",
            }
        ],
        [{"type": "response", "id": "register_0", "payload": {"pairingType": "PROMPT", "returnValue": True}}],
    ],
)
def test_a_tv_that_does_not_take_the_key_is_recorded_and_registered_with_once(tmp_path, answer):
    async def script(conn):
        await conn.recv()
        for a in answer:
            await conn.send(a)
        await conn.drain_until_close()

    b = Bench(tmp_path, script)
    assert b.go() == (REFUSED, 0.0)
    assert len(b.refused) == 1 and b.tv.connections == 1
    assert sum(1 for m in b.tv.received if m.get("type") == "register") == 1
    assert [k for k, _ in b.lines()] == ["watch.refused"]


def test_a_tv_that_accepts_and_then_says_nothing_is_a_failed_attempt_within_the_limit(tmp_path):
    async def silent(conn):
        await conn.recv()
        await conn.drain_until_close()  # it reads on, and never answers

    b = Bench(tmp_path, silent)
    assert b.go() == (FAILED, 0.0)
    assert b.lines() == [("session.fail", {"error": "TimeoutError"})]
    assert (
        b.tv.closes == [1000] and b.refused == []
    )  # silence is not a refusal, and the socket is closed properly


def test_a_tv_that_is_not_listening_is_a_failed_attempt(tmp_path):
    b = Bench(tmp_path, lambda c: serve(c))
    assert b.go(port=1) == (FAILED, 0.0)
    kind, fields = b.lines()[0]
    assert kind == "session.fail" and fields["error"] in (
        "ConnectionRefusedError",
        "OSError",
        "PermissionError",
    )
    assert b.tv.connections == 0


def test_a_tv_that_stops_answering_pings_is_lost_not_switched_off(tmp_path):
    def script(conn):
        conn.tv.answer_pings = False
        return serve(conn, [push("power", state="Active"), push("app", appId="netflix")])

    b = Bench(tmp_path, script)
    outcome, up = b.go()
    assert outcome == LOST and 0.3 <= up < 3
    assert b.lines()[-1] == ("session.down", {"why": "ProbeError"})
    assert not any(k == "power" and f.get("state") != "Active" for k, f in b.lines())


def test_a_tv_that_hangs_up_is_lost(tmp_path):
    async def hang_up(conn):
        conn.writer.close()

    b = Bench(tmp_path, lambda c: serve(c, [push("app", appId="netflix")], then=hang_up))
    outcome, _ = b.go()
    assert outcome == LOST and b.lines()[-1][0] == "session.down"


def test_a_frame_over_the_cap_ends_the_session(tmp_path):
    import struct

    async def huge(conn):
        conn.writer.write(bytes([0x81, 127]) + struct.pack("!Q", 2 << 20))  # 2 MiB announced, none sent
        await conn.writer.drain()

    b = Bench(tmp_path, lambda c: serve(c, then=huge))
    outcome, _ = b.go()
    assert outcome == LOST and b.lines()[-1] == ("session.down", {"why": "FrameTooBig"})
    assert 1009 in b.tv.closes


def test_a_refused_subscription_ends_the_session_as_unsupported(tmp_path):
    err = {"type": "error", "id": "app", "error": "404 no such service or method", "payload": {}}
    b = Bench(tmp_path, lambda c: serve(c, [push("power", state="Active"), err]))
    outcome, _ = b.go()
    assert outcome == UNSUPPORTED
    assert b.lines()[-2:] == [("sub.err", {"sub": "app"}), ("session.down", {"why": "unsupported"})]


def test_a_stop_closes_the_session_with_a_close_frame(tmp_path):
    async def stop_soon(bench):
        await asyncio.sleep(0.3)
        bench.stop = True

    b = Bench(tmp_path, lambda c: serve(c, [push("power", state="Active"), push("app", appId="netflix")]))
    outcome, up = b.go(during=stop_soon)
    assert outcome == STOPPED and up >= 0.2
    assert b.lines()[-1] == ("session.down", {"why": "stopped"}) and b.tv.closes == [1000]


def test_a_session_that_answers_its_pings_says_so_now_and_then(tmp_path):
    async def stop_later(bench):
        await asyncio.sleep(1.0)
        bench.stop = True

    b = Bench(tmp_path, lambda c: serve(c, [push("app", appId="netflix")]))
    b.go(during=stop_later)
    assert 1 <= sum(1 for k, _ in b.lines() if k == "alive") <= 5 and b.tv.pongs >= 3


def test_an_hourly_reading_that_found_no_tv_while_the_session_held_makes_the_service_stand_down(tmp_path):
    """Two sessions on one key that do not get along: the old reading must not lose a second hour."""
    rules = dataclasses.replace(FAST, conflict_after=0.3)

    async def reading_fails(bench):
        await asyncio.sleep(0.6)
        bench.history = (T0 + asyncio.get_running_loop().time(), "unreachable")

    b = Bench(
        tmp_path, lambda c: serve(c, [push("power", state="Active"), push("app", appId="netflix")]), rules
    )
    outcome, _ = b.go(during=reading_fails)
    assert outcome == CONFLICT and len(b.stood_down) == 1 and b.tv.closes == [1000]
    assert b.lines()[-1] == ("session.down", {"why": "conflict"})


def test_a_reading_from_before_the_session_or_one_that_reached_the_tv_is_no_conflict(tmp_path):
    rules = dataclasses.replace(FAST, conflict_after=0.3)

    async def readings(bench):
        bench.history = (T0 + asyncio.get_running_loop().time() - 50, "unreachable")  # before the session
        await asyncio.sleep(0.5)
        bench.history = (T0 + asyncio.get_running_loop().time(), "Active")
        await asyncio.sleep(0.5)
        bench.stop = True

    b = Bench(tmp_path, lambda c: serve(c, [push("app", appId="netflix")]), rules)
    outcome, _ = b.go(during=readings)
    assert outcome == STOPPED and b.stood_down == []


@pytest.mark.parametrize(("step", "restated_after"), [(400.0, 0.0), (-0.6, 0.5)])
def test_a_clock_that_is_set_is_written_down_and_the_tvs_state_said_again(tmp_path, step, restated_after):
    async def set_clock(bench):
        await asyncio.sleep(0.4)
        bench.wall_ahead = step
        await asyncio.sleep(1.6)
        bench.stop = True

    rules = dataclasses.replace(FAST, clock_step=0.5)
    b = Bench(
        tmp_path,
        lambda c: serve(c, [push("power", state="Screen Saver"), push("app", appId="netflix")]),
        rules,
    )
    b.go(during=set_clock)
    with open(tmp_path / "events.log", encoding="utf-8") as fh:
        recs = [json.loads(line) for line in fh]
    i = next(n for n, r in enumerate(recs) if r["kind"] == "clock")
    assert recs[i]["step"] == pytest.approx(step, abs=0.05)
    again = [r for r in recs[i + 1 :] if r["kind"] in ("power", "app")]
    assert [(r["kind"], r.get("state") or r.get("appId")) for r in again] == [
        ("power", "Screen Saver"),
        ("app", "netflix"),
    ]
    assert again[0]["t"] - recs[i]["t"] >= restated_after - 0.05  # not inside the seconds that happen twice
    # and the sessions built from the file put nothing in the stretch the step spoiled
    evs = appfront.read_events(str(tmp_path / "events.log"))
    tl = appfront.timeline(evs, [], min(e.t for e in evs) - 10, max(e.t for e in evs) + 10)
    gaps = appfront._clock_gaps(evs)
    assert gaps and all(s.end <= g0 or s.start >= g1 for s in tl.sessions for g0, g1 in gaps)


# ---- the loop and the session together ---------------------------------------------------------------------
def test_the_whole_service_against_a_tv_that_drops_every_session_stops_at_the_ceiling(tmp_path):
    """The real loop, the real session and a real socket, with an hour that lasts 3 s."""

    async def drop(conn):
        await conn.recv()
        await conn.send(REGISTERED)

    rules = dataclasses.replace(
        FAST,
        hour=3.0,
        backoff=(0.02,),
        min_gap=0.02,
        tick=0.02,
        traffic_trusted=10**9,
        give_up=10**9,
        yield_s=0.0,
    )
    counter = iter(range(0, 10**9, 100_000))

    async def main():
        tv = FakeTv(drop)
        port = await tv.start()
        loop = asyncio.get_running_loop()
        stop_at = loop.time() + 1.5
        bench = Bench(tmp_path, drop, rules)
        env = dataclasses.replace(
            bench.env(port), rx_bytes=lambda: next(counter), stopping=lambda: loop.time() >= stop_at
        )
        ledger = Ledger(str(tmp_path / "attempts"), hour=3.0)
        ledger.create()
        log = tvlive.EventLog(str(tmp_path / "events.log"), clock=env.clock)
        traffic_window = tvlive.Traffic
        try:
            tvlive.Traffic = lambda: traffic_window(need=1, seconds=5.0)
            rc = await tvlive.run(env, ledger, log, rules)
        finally:
            tvlive.Traffic = traffic_window
        log.close()
        await tv.stop()
        return rc, tv

    rc, tv = run(main())
    assert rc == 0 and tv.connections == tvlive.SERVICE_LIMIT


# ---- the gateway's side --------------------------------------------------------------------------------------
def test_the_newest_hourly_reading_is_read_from_the_end_of_the_history(tmp_path):
    path = tmp_path / "tvcheck-history.log"
    assert tvlive.last_reading(str(path)) is None
    path.write_text("x" * 2000 + "\n2026-11-05T19:20:03-06:00\tunreachable\t\n", encoding="utf-8")
    t, power = tvlive.last_reading(str(path))
    assert power == "unreachable" and t == pytest.approx(1793928003.0)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("2026-11-05T20:20:04-06:00\tActive\tyoutube.leanback.v4\n\n")
    assert tvlive.last_reading(str(path))[1] == "Active"
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("not a line\n")
    assert tvlive.last_reading(str(path)) is None
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("yesterday\tActive\t\n")
    assert tvlive.last_reading(str(path)) is None


def test_standing_down_leaves_a_marker_only_the_owner_takes_away(tmp_path):
    key_file = str(tmp_path / "lgtv-keys.sqlite")
    assert tvlive.stood_down(key_file) is None and tvlive.resume(key_file) is False
    tvlive.stand_down(key_file, "the hourly reading could not reach the TV while the live reading held it")
    assert "could not reach the TV" in tvlive.stood_down(key_file)
    assert tvlive.resume(key_file) is True and tvlive.stood_down(key_file) is None


def test_the_port_counter_reader_says_none_where_the_kernel_does_not_say():
    assert tvlive.rx_reader("no-such-interface-0")() is None


# ---- the hourly reading shares the count -----------------------------------------------------------------------
def test_the_hourly_reading_counts_its_two_connections_where_the_live_reading_runs(tmp_path, monkeypatch):
    key_file = str(tmp_path / "lgtv-keys.sqlite")
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv, {TV: "stored-key"}, key_file)
    led = Ledger(tvlive.state_path(key_file, tvlive.ATTEMPTS_FILE))
    assert lgwebos.read(TV, key_file).reachable
    assert not os.path.exists(led.path)  # the default: the file is never made, the reading as it was
    assert sorted(os.listdir(tmp_path)) == ["lgtv-keys.sqlite"]
    led.create()
    assert lgwebos.read(TV, key_file).reachable and counts["connect"] == 2
    recent = led.recent(1793026800.0)  # the suite's frozen clock
    assert [who for _, who in recent] == [HOURLY, HOURLY]  # its handshake, and the library's connection


def test_a_reading_that_asks_nothing_counts_nothing(tmp_path, monkeypatch):
    """Not paired, or refused: no connection is opened, so none is counted."""
    key_file = str(tmp_path / "lgtv-keys.sqlite")
    tv, _ = counting_lgtv()
    fake_lgtv(monkeypatch, tv, {}, key_file)
    led = Ledger(tvlive.state_path(key_file, tvlive.ATTEMPTS_FILE))
    led.create()
    assert lgwebos.read(TV, key_file).error == lgwebos.NOT_PAIRED
    assert led.recent(1793026800.0) == []


# ---- the store's side ------------------------------------------------------------------------------------------
def settings(tmp_path, **kw) -> config.Settings:
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    return config.Settings(state_dir=str(state), db_path=str(state / "tvgw.db"), **kw)


def write_events(s, lines: list[dict]) -> str:
    path = os.path.join(s.state_dir, tvlive.EVENTS_FILE)
    with open(path, "a", encoding="utf-8") as fh:
        for rec in lines:
            fh.write(json.dumps(rec) + "\n")
    return path


def test_the_ingest_loads_each_event_once_at_its_own_time_beside_the_hourly_readings(tmp_path):
    s = settings(tmp_path)
    now = 1793026800.0  # the suite's frozen clock
    conn = db.connect(s.db_path)
    conn.execute("INSERT INTO tvstate(t, power, app) VALUES (?, 'Active', 'netflix')", (now - 100,))
    write_events(
        s,
        [
            {"t": now - 500, "kind": "watch.start"},
            {"t": now - 400, "kind": "session.up"},
            {"t": now - 399.5, "kind": "power", "state": "Active"},
            {"t": now - 399.4, "kind": "app", "appId": "netflix"},
            {"t": now - 300, "kind": "watch.idle", "why": "not paired"},  # the service's own note: no event
            {"t": now - 200, "kind": "session.down", "why": "standby"},
        ],
    )
    assert ingest.ingest_tvlive(conn, s) == 5
    conn.commit()
    assert ingest.ingest_tvlive(conn, s) == 0  # nothing new: nothing twice
    write_events(s, [{"t": now - 50, "kind": "session.fail", "error": "TimeoutError"}])
    assert ingest.ingest_tvlive(conn, s) == 1
    conn.commit()
    got = appfront.stored_events(conn, 0, now)
    assert [(round(e.t - now, 1), e.kind, e.value, e.detail) for e in got] == [
        (-500, "watch", "start", ""),
        (-400, "conn", "up", ""),
        (-399.5, "power", "Active", ""),
        (-399.4, "app", "netflix", ""),
        (-200, "conn", "down", "standby"),
        (-50, "conn", "down", "TimeoutError"),
    ]
    assert conn.execute("SELECT COUNT(*) FROM tvstate").fetchone()[0] == 1  # the readings are untouched


def test_the_finer_record_is_kept_for_its_own_days_and_no_longer(tmp_path):
    s = settings(tmp_path, tv_events_days=3)
    now = 1793026800.0
    conn = db.connect(s.db_path)
    conn.execute("INSERT INTO tv_events(t, kind, value) VALUES (?, 'app', 'netflix')", (now - 4 * 86400,))
    conn.execute("INSERT INTO tv_events(t, kind, value) VALUES (?, 'app', 'amazon')", (now - 2 * 86400,))
    conn.execute("INSERT INTO tvstate(t, power, app) VALUES (?, 'Active', 'netflix')", (now - 4 * 86400,))
    write_events(s, [{"t": now - 5 * 86400, "kind": "app", "appId": "old"}, {"t": now - 60, "kind": "alive"}])
    assert ingest.ingest_tvlive(conn, s) == 1  # a line already too old is not loaded at all
    conn.commit()
    assert [e.value for e in appfront.stored_events(conn, 0, now) if e.kind == "app"] == ["amazon"]
    assert conn.execute("SELECT COUNT(*) FROM tvstate").fetchone()[0] == 1  # the hourly readings keep DB_DAYS


def test_the_finer_record_ages_out_with_the_live_reading_switched_off(tmp_path):
    """No events file any more: the rows still go on time, and the step says the file is missing in the
    way the ingest takes from an optional source."""
    s = settings(tmp_path)
    conn = db.connect(s.db_path)
    conn.execute(
        "INSERT INTO tv_events(t, kind, value) VALUES (?, 'app', 'netflix')", (1793026800.0 - 20 * 86400,)
    )
    with pytest.raises(ingest.SourceMissing):
        ingest.ingest_tvlive(conn, s)
    assert conn.execute("SELECT COUNT(*) FROM tv_events").fetchone()[0] == 0
    assert (
        "tvlive" in ingest.OPTIONAL_SOURCES and "tvlive" not in ingest.SOURCES
    )  # no warning, no coverage line


def test_a_whole_ingest_loads_the_events_and_a_gateway_without_them_is_as_it_was(gateway, lg):
    quiet = ingest.run(gateway, lg, extract=lambda p: [], oddport_lines=lambda s: [], gate_lines=lambda s: [])
    assert not any("tvlive" in w for w in quiet.warnings)
    write_events(
        gateway,
        [{"t": 1793026000.0, "kind": "session.up"}, {"t": 1793026001.0, "kind": "app", "appId": "netflix"}],
    )
    ingest.run(gateway, lg, extract=lambda p: [], oddport_lines=lambda s: [], gate_lines=lambda s: [])
    conn = db.connect(gateway.db_path, readonly=True)
    assert [(e.kind, e.value) for e in appfront.stored_events(conn, 0, 1e12)] == [
        ("conn", "up"),
        ("app", "netflix"),
    ]
    assert "tvlive" not in json.loads(db.get_meta(conn, "sources_read"))


def test_a_schema_11_store_gains_the_table_at_the_next_writer_and_keeps_its_rows(tmp_path):
    """The migration is the table's own CREATE IF NOT EXISTS: the release before knows no tv_events."""
    path = str(tmp_path / "s.db")
    old = db.connect(path)
    old.execute("DROP INDEX tv_events_t")
    old.execute("DROP TABLE tv_events")
    old.execute("INSERT INTO tvstate(t, power, app) VALUES (1.0, 'Active', 'netflix')")
    old.execute("UPDATE meta SET value = '11' WHERE key = 'schema'")
    old.commit()
    old.close()
    reader = db.connect(path, readonly=True)
    assert appfront.stored_events(reader, 0, 1e12) == []  # a reader of the old store finds no live record
    reader.close()
    conn = db.connect(path)
    assert db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION) == "12"
    assert conn.execute("SELECT COUNT(*) FROM tv_events").fetchone()[0] == 0
    assert conn.execute("SELECT power, app FROM tvstate").fetchall() == [("Active", "netflix")]
    names = {r[1] for r in conn.execute("PRAGMA index_list(tv_events)")}
    assert "tv_events_t" in names and "tv_events" in db.TABLES


def test_the_settings_take_on_or_off_and_a_whole_number_of_days(tmp_path):
    conf = tmp_path / "tvgw.conf"
    assert (config.Settings().live_reading, config.Settings().tv_events_days) == ("off", 14)
    conf.write_text("LIVE_READING=on\nTV_EVENTS_DAYS=30\n", encoding="utf-8")
    s = config.load(conf)
    assert (s.live_reading, s.tv_events_days) == ("on", 30)
    for bad, why in (("0", "at least 1"), ("366", "expected 1 to 365"), ("two", "TV_EVENTS_DAYS")):
        conf.write_text(f"TV_EVENTS_DAYS={bad}\n", encoding="utf-8")
        with pytest.raises(ValueError, match=why):
            config.load(conf)
    conf.write_text("LIVE_READING=yes\n", encoding="utf-8")
    with pytest.raises(ValueError, match="LIVE_READING='yes' in tvgw.conf: expected one of off, on"):  # noqa: RUF043
        config.load(conf)


def test_forget_takes_the_finer_record_and_keeps_what_the_ceiling_counts_with(tmp_path):
    assert forget.TABLES["tv_events"][0] == forget.FORGET and forget.TIME_COLUMNS["tv_events"] == "t"
    assert "tvlive" in forget.CURSORS
    for name, policy in (
        (tvlive.EVENTS_FILE, forget.FORGET),
        (tvlive.EVENTS_FILE + ".1", forget.FORGET),
        (tvlive.EVENTS_FILE + ".2.gz", forget.FORGET),
        (tvlive.ATTEMPTS_FILE, forget.KEEP),
        (tvlive.STOOD_DOWN_FILE, forget.KEEP),
    ):
        assert forget.classify(name, forget.STATE_ENTRIES)[0] == policy, name


def test_the_service_does_nothing_unless_it_is_switched_on_for_an_lg(tmp_path, capsys):
    key_file = str(tmp_path / "state" / "lgtv-keys.sqlite")
    assert tvlive.main(settings(tmp_path), key_file) == 0
    assert tvlive.main(settings(tmp_path, live_reading="on", profile="samsung-tizen"), key_file) == 0
    assert "nothing to do" in capsys.readouterr().out
    assert os.listdir(tmp_path / "state") == []  # no events file, no attempts file: nothing was made


def test_status_says_what_the_service_would_do_from_its_files_alone(tmp_path, monkeypatch):
    key_file = str(tmp_path / "state" / "lgtv-keys.sqlite")
    s = settings(tmp_path, live_reading="on")
    tv, counts = counting_lgtv()
    fake_lgtv(monkeypatch, tv)
    out = tvlive.status_lines(s, key_file, now=T0)
    assert out[0] == "LIVE_READING=on, PROFILE=lg-webos"
    assert any(line.startswith("not paired") for line in out) and "no record" in out[-1]
    fake_lgtv(monkeypatch, tv, {s.tv_ip: "stored-key"}, key_file)
    led = Ledger(tvlive.state_path(key_file, tvlive.ATTEMPTS_FILE))
    led.note(SERVICE, T0 - 10)
    led.note(HOURLY, T0 - 20)
    led.note(HOURLY, T0 - 4000)
    tvlive.stand_down(key_file, "12 attempts in a row failed")
    lgkeys.refused(key_file, s.tv_ip, "403 blacklisted")
    out = tvlive.status_lines(s, key_file, now=T0)
    assert out[1].startswith("the TV refused the key") and "sudo tvgw tvlive --resume" in out[2]
    assert out[3] == "connection attempts in the last hour: hourly 1, live 1 (the service stops at 6)"
    assert counts["connect"] == 0  # it connected to nothing
    off = tvlive.status_lines(settings(tmp_path), key_file, now=T0)
    assert off[1] == "the live reading is off: the service does not run"


# ---- one short session by the same rules: tvgw tvlive --listen, and the hardware test -------------------------
def paired(tmp_path, monkeypatch, power="Active", age=60.0, **kw):
    """A gateway paired with its TV whose last hourly reading, `age` seconds old, said `power`."""
    s = settings(tmp_path, **kw)
    key_file = os.path.join(s.state_dir, "lgtv-keys.sqlite")
    fake_lgtv(monkeypatch, counting_lgtv()[0], {s.tv_ip: "stored-key"}, key_file)
    history = os.path.join(s.state_dir, "tvcheck-history.log")
    stamp = datetime.fromtimestamp(time.time() - age).astimezone().isoformat(timespec="seconds")
    with open(history, "w", encoding="utf-8") as fh:
        fh.write(f"{stamp}\t{power}\tnetflix\n")
    return dataclasses.replace(s, tvcheck_history=history), key_file


def listen_to(monkeypatch, script, s, key_file, seconds=0.6):
    """`tvlive.hear` with the TV's address answered by a FakeTv on localhost."""
    import threading

    ready, done = threading.Event(), threading.Event()
    box = {}

    def serve_tv():
        async def main():
            tv = FakeTv(script)
            box["port"], box["tv"] = await tv.start(), tv
            ready.set()
            while not done.is_set():
                await asyncio.sleep(0.02)
            await asyncio.sleep(0.05)
            await tv.stop()

        asyncio.run(main())

    thread = threading.Thread(target=serve_tv, daemon=True)
    thread.start()
    assert ready.wait(5)

    async def connect_ws(ip, timeout):
        assert ip == s.tv_ip
        return await lgwebos._WebSocket.connect("127.0.0.1", box["port"], None, timeout=timeout)

    monkeypatch.setattr(lgwebos, "_connect_ws", connect_ws)
    try:
        return (*tvlive.hear(s, key_file, seconds), box["tv"])
    finally:
        done.set()
        thread.join(5)


def test_listening_hears_the_tv_and_closes_properly(tmp_path, monkeypatch):
    s, key_file = paired(tmp_path, monkeypatch)
    pushes = [push("power", state="Active"), push("app", appId="netflix")]
    outcome, lines, tv = listen_to(monkeypatch, lambda c: serve(c, pushes), s, key_file)
    assert outcome == STOPPED and tv.connections == 1 and tv.closes == [1000]
    assert [rec["kind"] for rec in lines] == ["session.up", "power", "app", "session.down"]
    assert [(m["type"], m.get("uri")) for m in tv.received] == [
        ("register", None),
        ("subscribe", lgwebos.POWER_URI),
        ("subscribe", lgwebos.APP_URI),
    ]
    # where the service never ran, nothing of the service's is left behind
    assert sorted(os.listdir(s.state_dir)) == ["lgtv-keys.sqlite", "tvcheck-history.log"]


def test_listening_counts_its_attempt_where_the_service_counts(tmp_path, monkeypatch):
    s, key_file = paired(tmp_path, monkeypatch)
    led = Ledger(tvlive.state_path(key_file, tvlive.ATTEMPTS_FILE))
    led.create()
    outcome, _, tv = listen_to(monkeypatch, lambda c: serve(c, [push("app", appId="netflix")]), s, key_file)
    assert outcome == STOPPED and [who for _, who in led.recent(time.time())] == ["listen"]
    for _ in range(5):
        led.note(SERVICE, time.time())
    outcome, lines, tv = listen_to(monkeypatch, lambda c: serve(c), s, key_file)
    assert (outcome, lines, tv.connections) == ("skipped: the hour's attempts are used", [], 0)


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"power": "unreachable"}, "skipped: no sign that the TV is on"),
        ({"age": 5000.0}, "skipped: no sign that the TV is on"),  # the reading is too old to say
        ({"profile": "samsung-tizen"}, "skipped: PROFILE=samsung-tizen has no live reading"),
    ],
)
def test_listening_connects_to_nothing_without_a_reading_that_found_the_tv_on(
    tmp_path, monkeypatch, change, why
):
    s, key_file = paired(tmp_path, monkeypatch, **change)
    outcome, lines, tv = listen_to(monkeypatch, lambda c: serve(c), s, key_file)
    assert (outcome, lines, tv.connections) == (why, [], 0)


def test_listening_connects_to_nothing_without_a_key_with_a_refusal_or_after_standing_down(
    tmp_path, monkeypatch
):
    s, key_file = paired(tmp_path, monkeypatch)
    tvlive.stand_down(key_file, "12 attempts in a row failed")
    outcome, _, tv = listen_to(monkeypatch, lambda c: serve(c), s, key_file)
    assert outcome.startswith("skipped: stood down") and tv.connections == 0
    tvlive.resume(key_file)
    lgkeys.refused(key_file, s.tv_ip, "403 blacklisted")
    outcome, _, tv = listen_to(monkeypatch, lambda c: serve(c), s, key_file)
    assert outcome == "skipped: the TV refused the key" and tv.connections == 0
    os.unlink(key_file)
    outcome, _, tv = listen_to(monkeypatch, lambda c: serve(c), s, key_file)
    assert outcome == "skipped: not paired" and tv.connections == 0


def test_a_tv_that_refuses_the_key_while_listening_is_recorded_for_the_hourly_reading_too(
    tmp_path, monkeypatch
):
    async def refuse(conn):
        await conn.recv()
        await conn.send({"type": "error", "id": "register_0", "error": "403 Pairing rejected"})
        await conn.drain_until_close()

    s, key_file = paired(tmp_path, monkeypatch)
    outcome, _, tv = listen_to(monkeypatch, refuse, s, key_file)
    assert outcome == REFUSED and tv.connections == 1
    assert lgkeys.record(key_file, s.tv_ip).refused
    assert lgwebos.read(s.tv_ip, key_file).error.startswith(lgwebos.KEY_REFUSED)  # and nothing is asked again


# ---- the command ---------------------------------------------------------------------------------------------
def test_the_command_says_its_status_resumes_and_checks_its_seconds(tmp_path, monkeypatch, capsys):
    s, key_file = paired(tmp_path, monkeypatch)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={s.state_dir}\nLIVE_READING=on\n", encoding="utf-8")
    base = ["--conf", str(conf), "tvlive", "--key-file", key_file]
    assert cli.main([*base, "--status"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("LIVE_READING=on, PROFILE=lg-webos\n") and "no record" in out
    assert cli.main([*base, "--resume"]) == 0
    assert "it had not stood down" in capsys.readouterr().out
    tvlive.stand_down(key_file, "12 attempts in a row failed")
    assert cli.main([*base, "--status"]) == 0
    assert "stood down" in capsys.readouterr().out
    assert cli.main([*base, "--resume"]) == 0
    assert "12 attempts in a row failed" in capsys.readouterr().out and tvlive.stood_down(key_file) is None
    for bad in ("0", "61"):
        assert cli.main([*base, "--listen", bad]) == 2
    assert "1 to 60 seconds" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main([*base, "--status", "--resume"])


def test_the_command_is_the_service_and_does_nothing_when_switched_off(tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "tvlive"]) == 0
    assert "LIVE_READING=off" in capsys.readouterr().out and os.listdir(tmp_path) == ["tvgw.conf"]


# ---- the watchdog's heartbeat ----------------------------------------------------------------------------------
def test_the_heartbeat_reaches_the_service_manager_and_is_silent_without_one(tmp_path):
    with tempfile.TemporaryDirectory(dir="/tmp") as short:  # a socket's path has a short limit
        path = os.path.join(short, "notify")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
            server.bind(path)
            server.settimeout(2)
            tvlive.heartbeat(path)()
            assert server.recv(64) == b"WATCHDOG=1"
    tvlive.heartbeat("")()  # no service manager: nothing happens
    tvlive.heartbeat(str(tmp_path / "gone"))()  # a socket that is not there: nothing is raised


# ---- the deploy tree, as text ------------------------------------------------------------------------------------
UNIT = (UNITS / "tvgw-tvlive.service").read_text(encoding="utf-8")
INSTALL_SH = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")


def test_the_unit_can_reach_nothing_but_the_tv_and_holds_no_capability():
    lines = UNIT.splitlines()
    for line in (
        "ExecStart=/usr/local/bin/tvgw tvlive",
        "CapabilityBoundingSet=",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ReadWritePaths=/var/lib/tvgw",
        "IPAddressDeny=any",
        "RestrictAddressFamilies=AF_INET AF_UNIX",
        "UMask=0077",
        "Restart=on-failure",  # an exit 0 with LIVE_READING=off stays down
        "After=tvgw.service",
        "Wants=tvgw.service",
    ):
        assert line in lines, line
    assert not [ln for ln in lines if ln.startswith(("IPAddressAllow=", "AmbientCapabilities=", "Requires="))]
    # the one address it may reach is written by install.sh from the settings
    assert (
        "printf '[Service]\\nIPAddressAllow=%s\\n' \"$TV_IP\" >/etc/systemd/system/tvgw-tvlive.service.d/tv.conf"
        in INSTALL_SH
    )
    # a restart never comes sooner than the watchdog and the restart delay let it: no tight loop
    assert "RestartSec=60" in lines and "WatchdogSec=180" in lines


def test_install_enables_it_restarts_it_on_a_changed_setting_and_removal_disables_it():
    assert "tvgw-dnsgate.service tvgw-tvlive.service tvgw-prune.timer" in INSTALL_SH
    assert "restart_changed tvgw-pcap tvgw-flowlog tvgw-dnsgate tvgw-tvlive\n" in INSTALL_SH
    assert "tvgw-dnsgate | tvgw-tvlive)" in INSTALL_SH
    prerm = (ROOT / "packaging" / "scripts" / "prerm").read_text(encoding="utf-8")
    assert "tvgw-dnsgate.service tvgw-tvlive.service >/dev/null" in prerm


def test_the_events_file_is_rotated_daily_and_kept_two_days():
    rotate = (ROOT / "deploy" / "logrotate" / "tvgw").read_text(encoding="utf-8")
    stanza = rotate[rotate.index("/var/lib/tvgw/tvlive-events.log {") :].split("}")[0]
    words = stanza.split()
    assert "daily" in words and words[words.index("rotate") + 1] == "2"
    assert {"copytruncate", "delaycompress", "compress", "missingok", "notifempty"} <= set(words)
    assert '"$statedir"/tvlive-events.log.*' in INSTALL_SH  # and install.sh trims the copies past them
    assert os.path.basename("/var/lib/tvgw/tvlive-events.log") == tvlive.EVENTS_FILE
