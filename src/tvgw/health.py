"""(reliability) The gateway's own health, sampled every 10 minutes beside the change ledger's counters,
and the findings that need the owner (design decision 73).

The reference gateway is an overclocked Raspberry Pi 5 that had a watchdog reset on 2026-10-31, keeps its
record on an SD card, and has a USB disk beside it that fails its SMART checks; nothing sampled its
temperature, its throttling, its memory, the card's writes, or the kernel's disk errors and USB resets, so a
box failing slowly was invisible until a check failed. Each source is optional, as the sampler's others are
(ledger.Sample): what a computer lacks stays NULL.

- `soc_temp`: the hottest of the kernel's thermal zones, in degrees Celsius.
- `throttled`: the Raspberry Pi firmware's flags (`vcgencmd get_throttled`): bits 0 to 3 say what holds
  now (under-voltage, frequency capped, throttled, soft temperature limit), bits 16 to 19 that it has
  happened since boot. NULL on a computer that is not a Pi.
- `mem_avail_pct`, `mem_psi_some`: MemAvailable as a share of MemTotal, and the kernel's cumulative
  microseconds in which some task waited for memory (`/proc/pressure/memory`, NULL without it).
- `disk_dev`, `disk_sectors_written`: the disk that holds STATE_DIR, the record's home, as the kernel names
  it (`mmcblk0`), and its 512-byte sectors written since boot (`/sys/block/<dev>/stat`).
- `io_errors`, `io_errors_store`, `usb_resets`: the kernel's lines since the previous sample that report a
  read or write error on any disk and on the record's disk, and a USB device reset (`journalctl -k`).

`findings()` reads a window of samples and says, in fixed words with counts, what needs the owner: the
firmware slowing the gateway, any disk error on the record's disk, disk errors elsewhere that rose from the
window before, and a USB device that reset. `tvgw verify`'s `gateway_health` check warns with them over the
last 24 hours, and the brief carries them as one red line. Temperature, memory and the card's writes are
shown, never a finding: no threshold for them was measured on this hardware.
"""

from __future__ import annotations

import dataclasses
import os
import re
import sqlite3
import subprocess
from collections.abc import Callable

from tvgw import db

WINDOW = 86400  # seconds: the window verify's check reads, and the brief's day
SECTOR = 512  # bytes: /sys/block/<dev>/stat counts in these, whatever the disk's own sector size
THROTTLE_NOW = 0xF
THROTTLE_SINCE_BOOT = 0xF0000
# each condition, by its bit in the low half (now) and the high half (since boot), in the firmware's order
THROTTLE_WORDS = ("under-voltage", "frequency capped", "throttled", "temperature limit")
VCGENCMD = ("vcgencmd", "get_throttled")
# a read or write error on a disk, as the block layer, the buffer cache, a filesystem or the SD card driver
# logs one; and a USB device the hub reset, as a disk on a failing bus does
IO_ERROR = re.compile(r"\bI/O error\b|\bmmcblk\d+: error -\d+")
IO_DEV = re.compile(r"\b(?:on )?dev(?:ice)? ([a-z][a-z0-9]*)|\b(mmcblk\d+): error")
USB_RESET = re.compile(r"\busb \d+-[\d.]+: reset .*USB device number \d+")
# the fields health adds to the sample, in the order the schema lists them
FIELDS = (
    "soc_temp",
    "throttled",
    "mem_avail_pct",
    "mem_psi_some",
    "disk_dev",
    "disk_sectors_written",
    "io_errors",
    "io_errors_store",
    "usb_resets",
)


def base_disk(name: str) -> str:
    """The disk a partition is on, as the kernel names both: mmcblk0p2 and nvme0n1p1 lose their `p<n>`,
    sda1 its digits."""
    m = re.fullmatch(r"(mmcblk\d+|nvme\d+n\d+|loop\d+)(?:p\d+)?", name)
    if m:
        return m.group(1)
    m = re.fullmatch(r"([a-z]+?)(\d+)", name)
    return m.group(1) if m and re.fullmatch(r"(?:sd|vd|hd|xvd)[a-z]+", m.group(1)) else name


def parse_throttled(text: str) -> int | None:
    """`throttled=0x50005` (vcgencmd), or the bare hex of the firmware's sysfs file."""
    m = re.search(r"(?:throttled=)?(?:0x)?([0-9a-fA-F]+)\s*$", text.strip())
    return int(m.group(1), 16) if text.strip() and m else None


def throttle_words(bits: int) -> list[str]:
    """The conditions a set of flags names, now or since boot alike, in the firmware's order."""
    return [w for i, w in enumerate(THROTTLE_WORDS) if bits & (1 << i) or bits & (1 << (i + 16))]


def parse_meminfo(text: str) -> float | None:
    vals = dict(re.findall(r"^(MemTotal|MemAvailable):\s+(\d+)", text, re.M))
    if "MemTotal" not in vals or "MemAvailable" not in vals or not int(vals["MemTotal"]):
        return None
    return round(100 * int(vals["MemAvailable"]) / int(vals["MemTotal"]), 1)


def parse_psi(text: str) -> int | None:
    m = re.search(r"^some\b.*\btotal=(\d+)", text, re.M)
    return int(m.group(1)) if m else None


def count_kernel(text: str, store_disk: str | None) -> tuple[int, int, int]:
    """(I/O error lines, those on `store_disk`, USB resets) in a stretch of the kernel's log."""
    io = io_store = usb = 0
    for line in text.splitlines():
        if USB_RESET.search(line):
            usb += 1
        if IO_ERROR.search(line):
            io += 1
            m = IO_DEV.search(line)
            dev = base_disk(m.group(1) or m.group(2)) if m else None
            if store_disk and dev == store_disk:
                io_store += 1
    return io, io_store, usb


def journal_since(since: float, until: float) -> str | None:
    """The kernel's lines between two times, text only; None when journalctl cannot say (missing, failed,
    over 10 seconds), so a missing source is a NULL and never a zero."""
    argv = [
        "journalctl",
        "-k",
        "-q",
        "--no-pager",
        "-o",
        "cat",
        f"--since=@{int(since)}",
        f"--until=@{int(until)}",
    ]
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


def store_disk(
    state_dir: str,
    stat: Callable[[str], os.stat_result] = os.stat,
    realpath: Callable[[str], str] = os.path.realpath,
    exists: Callable[[str], bool] = os.path.exists,
) -> str | None:
    """The disk under STATE_DIR as /sys/block names it, through its device number; None on a filesystem
    with no block device of its own (tmpfs, overlay, a btrfs subvolume) or when it cannot be read."""
    try:
        st = stat(state_dir)
    except OSError:
        return None
    node = realpath(f"/sys/dev/block/{os.major(st.st_dev)}:{os.minor(st.st_dev)}")
    if not node.startswith("/sys/") or not exists(node):
        return None
    if exists(os.path.join(node, "partition")):
        node = os.path.dirname(node)
    return os.path.basename(node)


def read(
    smp,
    state_dir: str,
    since: float | None,
    run: Callable[[list[str]], str],
    read_text: Callable[[str], str | None],
    which: Callable[[str], str | None],
    listdir: Callable[[str], list[str]],
    disk: Callable[[str], str | None] = store_disk,
    journal: Callable[[float, float], str | None] = journal_since,
) -> None:
    """Fill the health fields of `smp` (a ledger.Sample) from every source; what is missing stays None.
    `since` is the previous sample's time: the kernel's lines are counted from it to this sample's."""
    temps = []
    try:
        zones = [z for z in listdir("/sys/class/thermal") if z.startswith("thermal_zone")]
    except OSError:
        zones = []
    for zone in zones:
        raw = (read_text(f"/sys/class/thermal/{zone}/temp") or "").strip()
        if (
            raw.lstrip("-").isdigit() and 0 < int(raw) < 150_000
        ):  # millidegrees; a stuck or absent zone left out
            temps.append(int(raw) / 1000)
    smp.soc_temp = round(max(temps), 1) if temps else None
    tool = which(VCGENCMD[0])
    if tool:
        smp.throttled = parse_throttled(run([tool, VCGENCMD[1]]))
    smp.mem_avail_pct = parse_meminfo(read_text("/proc/meminfo") or "")
    smp.mem_psi_some = parse_psi(read_text("/proc/pressure/memory") or "")
    dev = disk(state_dir)
    if dev:
        fields = (read_text(f"/sys/block/{dev}/stat") or "").split()
        smp.disk_dev = dev
        smp.disk_sectors_written = int(fields[6]) if len(fields) > 6 and fields[6].isdigit() else None
    if since is not None and since < smp.t:
        text = journal(since, smp.t)
        if text is not None:
            smp.io_errors, smp.io_errors_store, smp.usb_resets = count_kernel(text, dev)


def previous_t(db_path: str) -> float | None:
    """The newest sample's time in the store, read-only; None without a store or a sample."""
    if not os.path.exists(db_path):
        return None
    try:
        conn = db.connect(db_path, readonly=True, timeout=10)
        try:
            row = conn.execute("SELECT MAX(t) FROM gw_samples").fetchone()
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return float(row[0]) if row and row[0] is not None else None


# ---- what the samples say -------------------------------------------------------------------------------
@dataclasses.dataclass
class Row:
    t: float
    boot_id: str | None
    soc_temp: float | None
    throttled: int | None
    mem_avail_pct: float | None
    disk_dev: str | None
    disk_sectors_written: int | None
    io_errors: int | None
    io_errors_store: int | None
    usb_resets: int | None


COLUMNS = tuple(f.name for f in dataclasses.fields(Row))


def rows(conn: sqlite3.Connection, a: float, b: float) -> list[Row]:
    """The samples in [a, b), oldest first; a store from before schema 14 reads its health fields as NULL."""
    have = {r[1] for r in conn.execute("PRAGMA table_info(gw_samples)")}
    cols = ", ".join(c if c in have else f"NULL AS {c}" for c in COLUMNS)
    return [
        Row(*r)
        for r in conn.execute(f"SELECT {cols} FROM gw_samples WHERE t >= ? AND t < ? ORDER BY t", (a, b))
    ]


def _sum(xs: list[Row], field: str) -> int:
    return sum(getattr(x, field) or 0 for x in xs)


def throttling(window: list[Row], before: Row | None) -> int:
    """The flags the window shows: every condition holding at a sample, and every one that newly happened
    since boot between two samples of one boot, or before the first sample of a boot."""
    bits = 0
    prev = before
    for x in window:
        if x.throttled is not None:
            bits |= x.throttled & THROTTLE_NOW
            same_boot = prev is not None and prev.boot_id == x.boot_id and prev.throttled is not None
            had = prev.throttled & THROTTLE_SINCE_BOOT if same_boot else 0  # type: ignore[union-attr]
            bits |= (x.throttled & THROTTLE_SINCE_BOOT) & ~had
        prev = x
    return bits


def written(window: list[Row], before: Row | None) -> int | None:
    """Bytes the record's disk took in the window: the rises of its counter between two samples of one
    boot and one disk. None when no pair of samples carries it."""
    total, seen, prev = 0, False, before
    for x in window:
        if (
            prev is not None
            and x.disk_sectors_written is not None
            and prev.disk_sectors_written is not None
            and prev.boot_id == x.boot_id
            and prev.disk_dev == x.disk_dev
        ):
            seen = True
            total += max(0, x.disk_sectors_written - prev.disk_sectors_written)
        prev = x
    return total * SECTOR if seen else None


@dataclasses.dataclass
class Summary:
    samples: int = 0
    findings: list[str] = dataclasses.field(default_factory=list)
    temp_max: float | None = None
    temp_last: float | None = None
    written: int | None = None  # bytes
    disk: str | None = None
    mem_avail_min: float | None = None
    io_errors: int = 0
    usb_resets: int = 0
    throttle_known: bool = False  # a sample carried the firmware's flags: "not slowed" means something
    slowed: list[str] = dataclasses.field(default_factory=list)  # the conditions, in the firmware's words

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def summarize(conn: sqlite3.Connection, a: float, b: float) -> Summary:
    """The window [a, b) against the one as long before it."""
    span = b - a
    every = rows(conn, a - span, b)
    window = [x for x in every if x.t >= a]
    earlier = [x for x in every if x.t < a]
    return findings(window, earlier[-1] if earlier else None, earlier)


def findings(window: list[Row], before: Row | None, earlier: list[Row]) -> Summary:
    out = Summary(samples=len(window))
    if not window:
        return out
    temps = [x.soc_temp for x in window if x.soc_temp is not None]
    out.temp_max, out.temp_last = (max(temps), temps[-1]) if temps else (None, None)
    mems = [x.mem_avail_pct for x in window if x.mem_avail_pct is not None]
    out.mem_avail_min = min(mems) if mems else None
    out.written = written(window, before)
    out.disk = next((x.disk_dev for x in reversed(window) if x.disk_dev), None)
    out.throttle_known = any(x.throttled is not None for x in window)
    bits = throttling(window, before)
    out.slowed = throttle_words(bits)
    if bits:
        out.findings.append("the firmware slowed the gateway: " + ", ".join(out.slowed))
    store = _sum(window, "io_errors_store")
    out.io_errors = _sum(window, "io_errors")
    other, other_before = out.io_errors - store, _sum(earlier, "io_errors") - _sum(earlier, "io_errors_store")
    if store:
        where = f" ({out.disk})" if out.disk else ""
        out.findings.append(f"the disk that holds the record{where} logged {store} read or write errors")
    if other and other > other_before:
        out.findings.append(f"another disk logged {other} read or write errors, up from {other_before}")
    out.usb_resets = _sum(window, "usb_resets")
    if out.usb_resets:
        out.findings.append(f"a USB device was reset {out.usb_resets} times")
    return out
