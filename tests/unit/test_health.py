"""(reliability) The gateway's own health (src/tvgw/health.py, design decision 73): each source read from
what the kernel and the Pi's firmware print, every source optional, the kernel's disk errors and USB
resets counted per sample, the findings a window gives and the ones it must not, the schema 14 columns on
an old store, verify's `gateway_health` and the brief's line and red line."""

import os
import sqlite3
import stat

import pytest
from conftest import NOW
from test_verify import S

from tvgw import cli, db, health, ledger, plain, queries, verify
from tvgw.config import Settings

# kernel lines as the reference's journal prints them, the device names generic
KERNEL = """\
usb 2-1: reset SuperSpeed USB device number 2 using xhci-hcd
sd 0:0:0:0: [sda] tag#3 uas_eh_abort_handler 0 uas-tag 1 inflight: CMD IN
I/O error, dev sda, sector 123456 op 0x0:(READ) flags 0x80700 phys_seg 1 prio class 2
Buffer I/O error on dev sda1, logical block 0, async page read
usb 1-1.3: reset high-speed USB device number 4 using xhci_hcd
usb 2-1: USB disconnect, device number 2
blk_update_request: I/O error, dev mmcblk0, sector 2048 op 0x1:(WRITE) flags 0x800 phys_seg 1 prio class 0
mmcblk0: error -110 transferring data, sector 4096, nr 8, cmd response 0x900, card status 0xc00
EXT4-fs (mmcblk0p2): mounted filesystem with ordered data mode
"""


def test_the_kernels_disk_errors_and_usb_resets_are_counted_and_placed():
    assert health.count_kernel(KERNEL, "mmcblk0") == (4, 2, 2)
    assert health.count_kernel(KERNEL, "sda") == (4, 2, 2)  # its partition's error counts for the disk
    assert health.count_kernel(KERNEL, None) == (4, 0, 2)
    assert health.count_kernel("", "mmcblk0") == (0, 0, 0)


@pytest.mark.parametrize(
    ("name", "disk"),
    [("mmcblk0p2", "mmcblk0"), ("mmcblk0", "mmcblk0"), ("nvme0n1p1", "nvme0n1"), ("sda1", "sda"),
     ("sdb", "sdb"), ("vda3", "vda"), ("dm-0", "dm-0"), ("loop7", "loop7")],
)  # fmt: skip
def test_a_partition_is_counted_for_its_disk(name, disk):
    assert health.base_disk(name) == disk


def test_the_firmwares_flags_are_read_both_ways_and_named():
    assert health.parse_throttled("throttled=0x50005\n") == 0x50005
    assert health.parse_throttled("50005\n") == 0x50005  # the firmware's own file prints bare hex
    assert health.parse_throttled("throttled=0x0") == 0
    assert health.parse_throttled("") is None
    assert health.throttle_words(0x50005) == ["under-voltage", "throttled"]
    assert health.throttle_words(0x80000) == ["temperature limit"]
    assert health.throttle_words(0) == []


def test_memory_is_read_from_meminfo_and_pressure():
    meminfo = "MemTotal:        8000000 kB\nMemFree:  100 kB\nMemAvailable:    2000000 kB\n"
    assert health.parse_meminfo(meminfo) == 25.0
    assert health.parse_meminfo("MemTotal: 0 kB\nMemAvailable: 0 kB\n") is None
    assert health.parse_meminfo("") is None
    psi = "some avg10=0.00 avg60=0.10 avg300=0.02 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=99\n"
    assert health.parse_psi(psi) == 123456 and health.parse_psi("") is None


def fake_stat(dev: int):
    return lambda path: os.stat_result((stat.S_IFDIR | 0o755, 0, dev, 0, 0, 0, 0, 0, 0, 0))


def test_the_record_s_disk_is_found_through_its_device_number():
    dev = os.makedev(179, 2)
    nodes = {"/sys/dev/block/179:2": "/sys/devices/platform/mmc0/block/mmcblk0/mmcblk0p2"}
    exists = {"/sys/devices/platform/mmc0/block/mmcblk0/mmcblk0p2",
              "/sys/devices/platform/mmc0/block/mmcblk0/mmcblk0p2/partition"}.__contains__  # fmt: skip
    found = health.store_disk("/var/lib/tvgw", fake_stat(dev), lambda p: nodes.get(p, p), exists)
    assert found == "mmcblk0"
    whole = health.store_disk(
        "/var/lib/tvgw",
        fake_stat(dev),
        lambda p: "/sys/devices/x/block/sda",
        {"/sys/devices/x/block/sda"}.__contains__,
    )
    assert whole == "sda"
    # tmpfs, overlay: an anonymous device with no node of its own
    assert health.store_disk("/run", fake_stat(os.makedev(0, 27)), lambda p: p, lambda p: False) is None

    def gone(path):
        raise FileNotFoundError(path)

    assert health.store_disk("/nowhere", gone) is None


def reader(
    files: dict[str, str], tools: dict[str, str], zones=("thermal_zone0", "thermal_zone1", "cooling_device0")
):
    return {
        "run": lambda cmd: tools.get(cmd[0], ""),
        "read_text": files.get,
        "which": lambda name: name if name in tools else None,
        "listdir": lambda path: list(zones),
    }


PI_FILES = {
    "/sys/class/thermal/thermal_zone0/temp": "54123\n",
    "/sys/class/thermal/thermal_zone1/temp": "0\n",  # a stuck zone is left out
    "/proc/meminfo": "MemTotal: 8000000 kB\nMemAvailable: 6000000 kB\n",
    "/proc/pressure/memory": "some avg10=0.00 avg60=0.00 avg300=0.00 total=777\n",
    "/sys/block/mmcblk0/stat": "1000 20 8000 300 500 40 123456 900 0 1200 1500 0 0 0 15 77 0\n",
}


def test_every_source_is_read_into_the_sample():
    smp = ledger.Sample(t=NOW)
    asked = []
    health.read(
        smp, "/var/lib/tvgw", NOW - 600, **reader(PI_FILES, {"vcgencmd": "throttled=0x50000\n"}),
        disk=lambda d: "mmcblk0", journal=lambda a, b: asked.append((a, b)) or KERNEL,
    )  # fmt: skip
    assert (smp.soc_temp, smp.throttled, smp.mem_avail_pct, smp.mem_psi_some) == (54.1, 0x50000, 75.0, 777)
    assert (smp.disk_dev, smp.disk_sectors_written) == ("mmcblk0", 123456)
    assert (smp.io_errors, smp.io_errors_store, smp.usb_resets) == (4, 2, 2)
    assert asked == [(NOW - 600, NOW)]  # from the previous sample to this one


def test_what_a_computer_lacks_stays_null_and_never_a_zero():
    smp = ledger.Sample(t=NOW)
    health.read(
        smp,
        "/var/lib/tvgw",
        NOW - 600,
        **reader({}, {}, zones=()),
        disk=lambda d: None,
        journal=lambda a, b: None,
    )
    assert all(getattr(smp, f) is None for f in health.FIELDS)
    first = ledger.Sample(t=NOW)  # the first sample has no previous one: no stretch of the log to count
    health.read(
        first, "/x", None, **reader(PI_FILES, {}), disk=lambda d: "mmcblk0", journal=lambda a, b: KERNEL
    )
    assert first.io_errors is None and first.usb_resets is None and first.throttled is None


def row(t, boot="b1", temp=50.0, thr=0, mem=60.0, dev="mmcblk0", sectors=None, io=0, io_store=0, usb=0):
    return health.Row(t, boot, temp, thr, mem, dev, sectors, io, io_store, usb)


def test_a_quiet_day_gives_its_numbers_and_no_finding():
    day = [row(NOW - 3600 * h, sectors=1000 * (24 - h), temp=50.0 + h % 3) for h in range(23, -1, -1)]
    out = health.findings(day, None, [])
    assert out.findings == [] and out.samples == 24 and out.throttle_known and out.slowed == []
    assert out.temp_max == 52.0 and out.written == 23 * 1000 * health.SECTOR and out.disk == "mmcblk0"


def test_the_firmware_slowing_the_gateway_is_a_finding_now_or_newly_since_boot():
    now = health.findings([row(NOW, thr=0x4)], row(NOW - 600), [])
    assert now.findings == ["the firmware slowed the gateway: throttled"]
    newly = health.findings([row(NOW - 600, thr=0), row(NOW, thr=0x10000)], None, [])
    assert newly.findings == ["the firmware slowed the gateway: under-voltage"]
    at_boot = health.findings([row(NOW, boot="b2", thr=0x10000)], row(NOW - 600, boot="b1"), [])
    assert at_boot.slowed == ["under-voltage"]  # happened between the boot and the first sample
    # an event from before the window, still flagged since boot, does not come back every day
    old = health.findings([row(NOW, thr=0x10000)], row(NOW - 600, thr=0x10000), [])
    assert old.findings == [] and old.throttle_known
    # a computer that is not a Pi says nothing of being slowed
    assert not health.findings([row(NOW, thr=None)], None, []).throttle_known


def test_disk_errors_on_the_records_disk_always_count_and_elsewhere_only_when_rising():
    store = health.findings([row(NOW, io=3, io_store=3)], None, [])
    assert store.findings == ["the disk that holds the record (mmcblk0) logged 3 read or write errors"]
    rising = health.findings([row(NOW, io=12)], None, [row(NOW - 86400, io=5)])
    assert rising.findings == ["another disk logged 12 read or write errors, up from 5"]
    steady = health.findings([row(NOW, io=5)], None, [row(NOW - 86400, io=5)])
    assert steady.findings == [] and steady.io_errors == 5


def test_a_usb_device_that_resets_is_a_finding():
    assert health.findings([row(NOW, usb=2)], None, []).findings == ["a USB device was reset 2 times"]


def test_the_cards_writes_count_within_one_boot_and_one_disk():
    seq = [
        row(NOW - 1200, sectors=100),
        row(NOW - 600, boot="b2", sectors=10),
        row(NOW, boot="b2", sectors=30),
    ]
    assert health.written(seq, None) == 20 * health.SECTOR  # the reboot's reset is not a negative
    swapped = [row(NOW - 600, sectors=100), row(NOW, dev="sda", sectors=500)]
    assert health.written(swapped, None) is None  # another disk: nothing to compare
    assert health.findings([], None, []).samples == 0


def store_with(tmp_path, samples: list[ledger.Sample]) -> sqlite3.Connection:
    conn = db.connect(str(tmp_path / "tvgw.db"))
    for smp in samples:
        ledger.record_sample(conn, smp)
    return conn


def test_the_store_keeps_the_columns_and_a_day_summarizes_against_the_one_before(tmp_path):
    def smp(t, **kw):
        return ledger.Sample(t=t, boot_id="b1", **kw)

    conn = store_with(
        tmp_path,
        [smp(NOW - 90000, io_errors=1, io_errors_store=0), smp(NOW - 3600, soc_temp=61.5, throttled=0, io_errors=4,
         io_errors_store=0, usb_resets=1, disk_dev="mmcblk0", disk_sectors_written=10, mem_avail_pct=48.0),
         smp(NOW - 600, soc_temp=55.0, throttled=0, disk_dev="mmcblk0", disk_sectors_written=2058)],
    )  # fmt: skip
    out = health.summarize(conn, NOW - 86400, NOW)
    assert out.samples == 2 and out.temp_max == 61.5 and out.mem_avail_min == 48.0
    assert out.written == 2048 * 512
    assert out.findings == [
        "another disk logged 4 read or write errors, up from 1",
        "a USB device was reset 1 times",
    ]


def test_a_schema_13_store_gains_the_health_columns_and_keeps_its_samples(tmp_path):
    path = tmp_path / "tvgw.db"
    conn = db.connect(str(path))
    for column in health.FIELDS:
        conn.execute(f"ALTER TABLE gw_samples DROP COLUMN {column}")
    conn.execute("INSERT INTO gw_samples(t, boot_id) VALUES (?, 'b1')", (NOW - 600,))
    conn.execute("UPDATE meta SET value = '13' WHERE key = 'schema'")
    conn.commit()
    conn.close()
    ro = db.connect(str(path), readonly=True)  # a reader before any writer: the fields read as NULL
    (old,) = health.rows(ro, NOW - 3600, NOW)
    assert old.soc_temp is None and old.usb_resets is None
    ro.close()
    conn = db.connect(str(path))
    have = {r[1] for r in conn.execute("PRAGMA table_info(gw_samples)")}
    assert set(health.FIELDS) <= have
    assert db.get_meta(conn, "schema") == str(db.SCHEMA_VERSION) and db.SCHEMA_VERSION >= 14
    assert conn.execute("SELECT boot_id FROM gw_samples").fetchall() == [("b1",)]


def test_previous_t_is_the_newest_sample_or_none(tmp_path):
    assert health.previous_t(str(tmp_path / "none.db")) is None
    conn = store_with(tmp_path, [ledger.Sample(t=NOW - 1200), ledger.Sample(t=NOW - 600)])
    conn.close()
    assert health.previous_t(str(tmp_path / "tvgw.db")) == NOW - 600


# ---- verify, the brief ----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("s", "view", "level", "detail"),
    [
        (Settings(ledger="off"), None, verify.OK, "not sampled (LEDGER=off)"),
        (S, None, verify.OK, "the store could not be read"),
        (S, health.Summary(), verify.OK, "no gateway samples in the last 24 hours"),
        (S, health.Summary(samples=3, temp_last=52.4, throttle_known=True), verify.OK,
         "52 °C, not slowed, no disk errors or USB resets in the last 24 hours"),
        (S, health.Summary(samples=3, temp_last=40.0), verify.OK,
         "40 °C, no disk errors or USB resets in the last 24 hours"),
        (S, health.Summary(samples=3, findings=["a USB device was reset 2 times"]), verify.WARN,
         "in the last 24 hours a USB device was reset 2 times"),
    ],
)  # fmt: skip
def test_the_check_warns_with_the_findings_and_says_the_temperature_otherwise(s, view, level, detail):
    assert verify.health_level(s, view) == (level, detail)


def test_the_check_is_a_warning_at_most_whatever_it_finds(lg):
    from test_verify import gateway, resolver

    view = health.Summary(
        samples=1, findings=["the disk that holds the record (mmcblk0) logged 9 read or write errors"]
    )
    r = verify.check(S, lg, **gateway(health_view=view), resolve=resolver())
    (c,) = [c for c in r.checks if c.name == "gateway_health"]
    assert c.ok and c.warn and "mmcblk0" in c.detail and r.ok


def test_the_sampler_adds_health_and_a_health_failure_keeps_the_ledgers_sample(monkeypatch, capsys):
    monkeypatch.setattr(ledger, "sample", lambda s: ledger.Sample(t=NOW, boot_id="b1"))
    monkeypatch.setattr(health, "previous_t", lambda path: NOW - 600)
    seen = []
    monkeypatch.setattr(
        health, "read", lambda smp, state, since, **kw: seen.append(since) or setattr(smp, "soc_temp", 49.0)
    )
    smp = verify.gw_sample(S)
    assert smp.soc_temp == 49.0 and seen == [NOW - 600]

    def broken(*a, **kw):
        raise RuntimeError("no /sys here")

    monkeypatch.setattr(health, "read", broken)
    smp = verify.gw_sample(S)
    assert smp is not None and smp.boot_id == "b1"
    assert "the gateway's health sample failed: RuntimeError: no /sys here" in capsys.readouterr().err


def test_a_finding_is_one_red_line_in_the_doctors_tier_and_nothing_else_is_one():
    found = {"findings": ["the firmware slowed the gateway: under-voltage", "a USB device was reset 1 times"]}
    lines = queries.red_lines({"gateway_health": found})
    assert lines == [
        "gateway hardware: the firmware slowed the gateway: under-voltage; a USB device was reset 1 times"
    ]
    assert plain.tier(lines[0])[0] == "doctor"
    quiet = {"findings": [], "temp_max": 79.0, "written": 2**33, "mem_avail_min": 3.0}
    assert queries.red_lines({"gateway_health": quiet}) == []  # heat, writes and memory are shown, never red


def test_the_brief_line_shows_the_numbers_and_waits_for_samples_that_carry_them():
    h = health.Summary(
        samples=144,
        temp_max=61.4,
        throttle_known=True,
        written=312 * 2**20,
        disk="mmcblk0",
        mem_avail_min=48.2,
    ).as_dict()
    assert cli.health_line(h) == (
        "Gateway health: SoC 61 °C at most, not slowed; mmcblk0 took 312.0M of writes; at least 48% of memory"
        " free; no disk errors, no USB resets"
    )
    h.update(slowed=["under-voltage"], io_errors=3, usb_resets=1)
    assert "slowed: under-voltage" in cli.health_line(h) and cli.health_line(h).endswith(
        "3 disk errors, 1 USB reset"
    )
    assert cli.health_line(health.Summary(samples=10).as_dict()) is None  # samples from before schema 14
    assert cli.health_line(None) is None and cli.health_line(health.Summary().as_dict()) is None
