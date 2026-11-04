"""`tvgw tv quiet` (design decision 63): a deploy that changes the network runs only inside the
window, with the TV not Active and its port idle, and the one line it prints never says which of
these failed. The gateway is faked: a store with gateway samples, the TV's hourly history, and the
port's sysfs counters; the zone is conftest's America/Chicago."""

import dataclasses
import os
from datetime import datetime
from pathlib import Path

import pytest

from tvgw import cli, config, db, ledger, quiet
from tvgw.config import Settings

BOOT = "0b3c5b8e-0d39-4c4f-9f4b-7d1b2f0a1c2e"
MB = quiet.IDLE_BYTES


def at(hh: int, mm: int) -> float:
    return datetime(2026, 11, 3, hh, mm).timestamp()


class Gateway:
    """A store with gateway samples, the TV's reading history and the TV port's counters."""

    def __init__(self, tmp_path, now: float):
        self.now = now
        self.s = Settings(db_path=str(tmp_path / "tvgw.db"), tvcheck_history=str(tmp_path / "history.log"))
        self.files: dict[str, str] = {quiet.BOOT_ID: BOOT + "\n"}
        self.port(rx=50 * MB, tx=10 * MB)
        self.slept: list[float] = []
        conn = db.connect(self.s.db_path)
        conn.close()

    def port(self, rx: int, tx: int, boot: str = BOOT) -> None:
        self.files[f"/sys/class/net/{self.s.tv_if}/statistics/rx_bytes"] = f"{rx}\n"
        self.files[f"/sys/class/net/{self.s.tv_if}/statistics/tx_bytes"] = f"{tx}\n"
        self.files[quiet.BOOT_ID] = boot + "\n"

    def sample(self, minutes_ago: float, rx: int, tx: int, boot: str | None = BOOT) -> None:
        conn = db.connect(self.s.db_path)
        try:
            smp = ledger.Sample(t=self.now - minutes_ago * 60, boot_id=boot, tv_rx_bytes=rx, tv_tx_bytes=tx)
            ledger.record_sample(conn, smp)
        finally:
            conn.close()

    def reading(self, power: str, minutes_ago: float = 20) -> None:
        stamp = datetime.fromtimestamp(self.now - minutes_ago * 60).astimezone().isoformat(timespec="seconds")
        with open(self.s.tvcheck_history, "a", encoding="utf-8") as fh:
            fh.write(f"{stamp}\t{power}\tcom.webos.app.home\n")

    def read(self, path: str) -> str | None:
        if path in self.files:
            return self.files[path]
        return quiet.read_text(path)

    def seams(self) -> dict:
        return {"clock": lambda: self.now, "sleep": self.slept.append, "read": self.read}

    def decide(self, window=None, idle=quiet.IDLE_MINUTES, wait=0) -> bool:
        return quiet.decide(self.s, window, idle, wait, **self.seams())


@pytest.fixture()
def gw(tmp_path):
    """04:00, inside the default window; the port moved 100 KB since a sample 25 minutes ago."""
    g = Gateway(tmp_path, at(4, 0))
    g.sample(25, rx=50 * MB - 80_000, tx=10 * MB - 20_000)
    g.sample(5, rx=50 * MB - 1000, tx=10 * MB)
    return g


def test_a_quiet_tv_inside_the_window_may_deploy(gw):
    gw.reading("Screen Off")
    assert gw.decide()


@pytest.mark.parametrize(
    ("hh", "mm", "inside"),
    [(3, 29, False), (3, 30, True), (4, 0, True), (5, 29, True), (5, 30, False), (21, 0, False)],
)
def test_the_window_holds_its_start_and_not_its_end(tmp_path, hh, mm, inside):
    g = Gateway(tmp_path, at(hh, mm))
    g.sample(30, rx=50 * MB, tx=10 * MB)
    assert g.decide() is inside


def test_a_window_past_midnight_and_the_settings_window(tmp_path):
    g = Gateway(tmp_path, at(0, 30))
    g.sample(30, rx=50 * MB, tx=10 * MB)
    assert g.decide("23:00-01:00") and not g.decide("01:00-02:00") and not g.decide()
    g.s = dataclasses.replace(g.s, deploy_window="00:15-00:45")
    assert g.decide()


def test_an_active_tv_defers_and_a_stale_or_standby_reading_does_not(gw):
    gw.reading("Active")
    assert not gw.decide()
    gw.reading("Active Standby", minutes_ago=10)  # the newest line counts
    assert gw.decide()
    gw.reading("Active", minutes_ago=quiet.READING_MAX_AGE / 60 + 1)  # appended last, but three hours old
    assert gw.decide()


def test_no_reader_is_no_objection(gw):
    """A TV without a LAN-API reader never writes the history: the port decides alone."""
    assert not os.path.exists(gw.s.tvcheck_history)
    assert gw.decide()


def test_a_busy_port_defers(gw):
    gw.port(rx=50 * MB + MB, tx=10 * MB)  # 1 MB and 100 KB since the sample 25 minutes ago
    assert not gw.decide()
    assert not gw.decide(idle=4)  # against the 5-minute sample: 1 MB and 1 KB, still over
    gw.port(rx=50 * MB, tx=10 * MB)
    assert gw.decide()


def test_a_port_nothing_can_measure_is_not_idle(gw, tmp_path):
    del gw.files[f"/sys/class/net/{gw.s.tv_if}/statistics/rx_bytes"]
    assert not gw.decide()  # no counters now
    (tmp_path / "fresh").mkdir()
    fresh = Gateway(tmp_path / "fresh", at(4, 0))
    fresh.sample(15, rx=50 * MB, tx=10 * MB)
    assert not fresh.decide()  # no sample old enough
    fresh.sample(25, rx=50 * MB, tx=10 * MB, boot="another-boot")
    assert not fresh.decide()  # a reboot between the sample and now
    fresh.sample(24, rx=60 * MB, tx=10 * MB)
    assert not fresh.decide()  # the count went down: a reset the boot id missed


def test_a_missing_or_old_store_is_unmeasured_and_the_wait_measures_instead(tmp_path):
    g = Gateway(tmp_path, at(4, 0))
    os.remove(g.s.db_path)
    assert not g.decide()
    g.s = dataclasses.replace(g.s, db_path=str(tmp_path / "nowhere" / "tvgw.db"))
    assert g.decide(wait=600)  # the counters did not move across the wait
    assert g.slept == [600]

    def busy(seconds):
        g.port(rx=60 * MB, tx=10 * MB)

    assert not quiet.decide(g.s, None, 20, 60, clock=lambda: g.now, sleep=busy, read=g.read)


def test_the_wait_must_agree_with_the_samples(gw):
    def busy(seconds):
        gw.port(rx=50 * MB + 2 * MB, tx=10 * MB)

    assert not quiet.decide(gw.s, None, 20, 30, clock=lambda: gw.now, sleep=busy, read=gw.read)


def test_the_store_is_only_read(gw):
    store = Path(gw.s.db_path)
    before = store.stat().st_mtime_ns, store.read_bytes()
    gw.decide()
    assert (store.stat().st_mtime_ns, store.read_bytes()) == before


def test_the_one_line_never_names_the_reason(gw, capsys):
    """Outside the window, an Active TV, a busy port, no counters: the same line, nothing on stderr."""
    cases = []

    def run(window=None):
        rc = quiet.main(gw.s, window, quiet.IDLE_MINUTES, 0, **gw.seams())
        cases.append((rc, capsys.readouterr()))

    run(window="05:30-06:30")
    gw.reading("Active")
    run()
    gw.reading("Screen Off", minutes_ago=1)
    gw.port(rx=90 * MB, tx=10 * MB)
    run()
    del gw.files[quiet.BOOT_ID]
    run()
    assert [(rc, out.out, out.err) for rc, out in cases] == [(1, "deploy: deferred\n", "")] * 4
    gw.port(rx=50 * MB, tx=10 * MB)
    assert quiet.main(gw.s, None, quiet.IDLE_MINUTES, 0, **gw.seams()) == 0
    assert capsys.readouterr() == ("deploy: now\n", "")


def test_an_unreadable_reading_is_deferred_not_no_reader(gw, capsys):
    def denied(path):
        if path == gw.s.tvcheck_history:
            raise PermissionError(13, "Permission denied", path)
        return gw.read(path)

    seams = {**gw.seams(), "read": denied}
    assert quiet.main(gw.s, None, quiet.IDLE_MINUTES, 0, **seams) == 1
    assert capsys.readouterr() == ("deploy: deferred\n", "")


def test_a_store_it_cannot_open_defers(gw, capsys):
    """Run without the rights to the store (or with none there), the idle minutes are unmeasured."""
    seams = {**gw.seams(), "connect": lambda path: db.connect(path + ".missing", readonly=True)}
    assert quiet.main(gw.s, None, quiet.IDLE_MINUTES, 0, **seams) == 1
    assert capsys.readouterr() == ("deploy: deferred\n", "")


def test_the_command_line(monkeypatch, capsys, tmp_path):
    seen = {}

    def fake(s, window, idle, wait):
        seen.update(window=window, idle=idle, wait=wait, deploy_window=s.deploy_window)
        print(quiet.NOW)
        return 0

    monkeypatch.setattr(quiet, "main", fake)
    conf = tmp_path / "tvgw.conf"
    conf.write_text("DEPLOY_WINDOW=02:00-04:00\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "tv", "quiet", "--wait", "0"]) == 0
    assert seen == {"window": None, "idle": 20, "wait": 0, "deploy_window": "02:00-04:00"}
    assert cli.main(["--conf", str(conf), "tv", "quiet", "--window", "23:00-01:00", "--idle", "5"]) == 0
    assert seen["window"] == "23:00-01:00" and seen["idle"] == 5
    capsys.readouterr()
    for bad in (
        ["--window", "3:30-5:30"],
        ["--window", "04:00-04:00"],
        ["--idle", "0"],
        ["--idle", "x"],
        ["--wait", "-1"],
        ["--wait", str(quiet.MAX_WAIT + 1)],
    ):
        with pytest.raises(SystemExit) as e:
            cli.main(["--conf", str(conf), "tv", "quiet", *bad])
        assert e.value.code == 2, bad
    with pytest.raises(SystemExit):
        cli.main(["tv"])  # the family needs its subcommand


@pytest.mark.parametrize(
    "value", ["03:30-05:30", "23:00-01:00", "00:00-23:59", "3:30-5:30", "04:00-04:00", "24:00-01:00", "x"]
)
def test_the_window_is_read_as_config_reads_deploy_window(tmp_path, value):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"DEPLOY_WINDOW={value}\n", encoding="utf-8")
    try:
        config.load(conf)
        accepted = True
    except ValueError:
        accepted = False
    try:
        quiet.parse_window(value)
        parsed = True
    except ValueError:
        parsed = False
    assert parsed is accepted


def test_the_history_line_is_read_as_tvgw_analyze_writes_it():
    now = at(4, 0)
    stamp = datetime.fromtimestamp(now - 600).astimezone().isoformat(timespec="seconds")
    assert quiet.last_power(f"{stamp}\tActive Standby\tcom.webos.app.home\n\n", now) == "Active Standby"
    assert quiet.last_power("2026-10-27 05:20 Active Standby netflix\n", now) is None  # pre-tab format
    assert quiet.last_power("garbage\tActive\t\n", now) is None
    future = datetime.fromtimestamp(now + 3600).astimezone().isoformat(timespec="seconds")
    assert quiet.last_power(f"{future}\tActive\t\n", now) is None
