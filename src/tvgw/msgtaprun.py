"""(msgtap) `tvgw experiment-tap`: the message tap's shadow run (design decision 101). It captures the
headers of the packets the TV sends with data in them, for some minutes and into memory, rebuilds them
into messages (`msgtap`), and returns what each server was sent and any steady beat of uploads. Then it
deletes the capture, whatever ends the run.

- **Where:** RUN_DIR, which must be on tmpfs, so the capture is held in memory and is written to no
  disk (a gateway that swaps to a disk may page it out). Only root may run it, and the directory is
  root's alone (0700).
- **What is captured** (`capture_filter`): packets from the TV's address, TCP, that carry data, SNAPLEN
  bytes of each: the frame's, IP's and TCP's headers, and never a byte of what the packet carries,
  whatever options its TCP header has. Nothing the TV receives and no bare acknowledgement, whose timing
  would be the rhythm of what the TV downloads.
- **For how long:** the minutes asked for, or until the file reaches SIZE_STOP_KB or half the free
  space of the tmpfs, the smaller, so a run cannot fill the memory the gateway's services run in. The
  rebuild keeps each flow's totals and only the uploads the test reads (`tally`), never every message.
- **Deleted always:** in a `finally`, and on SIGTERM and SIGHUP, which raise `Stopped` while it runs
  as Ctrl-C raises KeyboardInterrupt; a second signal waits until the file is gone. A capture left by a
  run that was killed outright is overwritten and deleted by the next run, and a reboot empties tmpfs.
  A lock on RUN_DIR keeps a second run from writing the same file, or deleting another run's.
- **Named:** a flow by the latest TLS hello the store holds for its address and ports, else by its
  server's /24 (`queries.acr_cell`).

It adds no firewall rule, opens no connection, writes nothing to the store and keeps nothing.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import re
import resource
import signal
import sqlite3
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from tvgw import msgtap
from tvgw.queries import acr_cell

RUN_DIR = "/run/tvgw-exp"
CAPTURE = "tap.pcap"
DUMPCAP = "/usr/bin/dumpcap"
SNAPLEN = 54  # Ethernet 14, IPv4 20, TCP 20: the reader needs 48 (50 cooked), and no payload byte is kept
SIZE_STOP_KB = 1_000_000  # dumpcap's unit is 1,000 bytes: about 1 GB
STOPS = (signal.SIGTERM, signal.SIGHUP)  # what ends a run as Ctrl-C does, the capture deleted
RX_COUNTER = "/sys/class/net/{}/statistics/rx_packets"
DROPPED = re.compile(r"received/dropped on interface '[^']*': \d+/(\d+)")
clock, cpu_time = time.monotonic, time.process_time  # what a run is timed by; a test stands in for both


class TapError(Exception):
    """The run cannot start, or its capture failed or cannot be read: nothing is concluded."""


class Stopped(Exception):
    """SIGTERM or SIGHUP ended the run before its minutes were up."""


@dataclass(frozen=True)
class Row:
    """What the TV sent one server name on one port: messages, payload bytes, the largest message, and
    the flows whose uploads kept a steady beat."""

    name: str
    port: int
    messages: int
    bytes: int
    largest: int
    flags: tuple[msgtap.Flag, ...] = ()


@dataclass(frozen=True)
class Result:
    seconds: float  # how long the capture ran
    rows: list[Row]
    counts: msgtap.Counts
    received: int | None  # packets the TV's port received in the run, every protocol (its counter)
    dropped: int | None  # packets the kernel dropped before dumpcap read them, as dumpcap says
    cpu_capture: float  # dumpcap's CPU seconds
    cpu_rebuild: float  # the reading and the rebuild's

    @property
    def data_packets(self) -> int:
        return self.counts.records - self.counts.skipped

    @property
    def flagged(self) -> bool:
        return any(r.flags for r in self.rows)

    @property
    def too_short(self) -> bool:
        """Whether the capture ran less than the IN_A_ROW windows a steady beat takes to show."""
        return self.seconds < msgtap.IN_A_ROW * msgtap.WINDOW


def capture_filter(tv_ip: str) -> str:
    """The TV's TCP packets that carry data: the IP length less the IP and TCP headers is above 0."""
    return f"src host {tv_ip} and tcp and (ip[2:2] - ((ip[0]&0xf)<<2) - ((tcp[12]&0xf0)>>2)) > 0"


def dumpcap_argv(dumpcap: str, tv_if: str, tv_ip: str, minutes: int, stop_kb: int, path: str) -> list[str]:
    """dumpcap writing a classic pcap (-P) quietly (-q), SNAPLEN bytes a packet, until either stop."""
    return [
        dumpcap, "-i", tv_if, "-q", "-P", "-s", str(SNAPLEN), "-f", capture_filter(tv_ip),
        "-a", f"duration:{minutes * 60}", "-a", f"filesize:{stop_kb}", "-w", path,
    ]  # fmt: skip


def on_tmpfs(path: str, mounts: str) -> bool:
    """Whether the mount that holds `path`, a real path, is a tmpfs, by the lines of /proc/self/mounts."""
    best, kind = "", ""
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        point = fields[1].replace("\\040", " ")
        inside = path == point or path.startswith(point.rstrip("/") + "/")
        if inside and len(point) >= len(best):
            best, kind = point, fields[2]
    return kind == "tmpfs"


def size_stop(free_bytes: int) -> int:
    """dumpcap's size stop, in its kB: SIZE_STOP_KB, or half the free space when that is less."""
    return min(SIZE_STOP_KB, free_bytes // 2 // 1000)


def names(conn: sqlite3.Connection | None, flows: Iterable[msgtap.Flow]) -> dict[msgtap.Flow, str]:
    """Each flow's name: the latest TLS hello the store holds for its address and ports, else its
    server's /24. A store that cannot be read names nothing, and the run's figures stand."""
    out = {}
    for flow in flows:
        sport, dst, dport = flow
        hello = None
        if conn is not None:
            with contextlib.suppress(sqlite3.Error):
                hello = conn.execute(
                    "SELECT sni FROM tls WHERE dst=? AND sport=? AND dport=? ORDER BY t DESC LIMIT 1",
                    (dst, sport, dport),
                ).fetchone()
        out[flow] = hello[0] if hello else acr_cell(None, dst)
    return out


def tally(messages: Iterable[msgtap.Message]) -> tuple[dict[msgtap.Flow, list[int]], list[msgtap.Message]]:
    """One pass over the messages: each flow's messages, bytes and largest, and the uploads the test reads
    (FLOOR bytes or more). Memory is the flows and the uploads, never every message."""
    totals: dict[msgtap.Flow, list[int]] = {}
    uploads = []
    for m in messages:
        t = totals.setdefault(m.flow, [0, 0, 0])
        t[0] += 1
        t[1] += m.bytes
        t[2] = max(t[2], m.bytes)
        if m.bytes >= msgtap.FLOOR:
            uploads.append(m)
    return totals, uploads


def rows(totals: dict[msgtap.Flow, list[int]], flags: Iterable[msgtap.Flag], named: dict) -> list[Row]:
    """The flows' totals and flags by server name and port, the most bytes first."""
    acc: dict[tuple[str, int], list] = {}
    for flow, (n, nbytes, largest) in totals.items():
        a = acc.setdefault((named[flow], flow[2]), [0, 0, 0, []])
        a[0] += n
        a[1] += nbytes
        a[2] = max(a[2], largest)
    for f in flags:
        acc[named[f.flow], f.flow[2]][3].append(f)
    out = [Row(name, port, n, b, big, tuple(fl)) for (name, port), (n, b, big, fl) in acc.items()]
    return sorted(out, key=lambda r: (-r.bytes, r.name, r.port))


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _counter(read: Callable[[str], str], tv_if: str) -> int | None:
    try:
        return int(read(RX_COUNTER.format(tv_if)).strip())
    except (OSError, ValueError):
        return None


def _children_cpu() -> float:
    use = resource.getrusage(resource.RUSAGE_CHILDREN)
    return use.ru_utime + use.ru_stime


def _stop(signum, _frame) -> None:
    raise Stopped(signal.Signals(signum).name)


def run(
    minutes: int,
    tv_if: str,
    tv_ip: str,
    conn: sqlite3.Connection | None,
    *,
    run_dir: str = RUN_DIR,
    dumpcap: str = DUMPCAP,
    euid: Callable[[], int] = os.geteuid,
    read: Callable[[str], str] = _read,
) -> Result:
    """Capture for `minutes`, rebuild, delete. TapError when it cannot start, dumpcap fails or the file
    cannot be read; Stopped when SIGTERM or SIGHUP ends it. The capture is gone when this returns or
    raises, whatever it raises."""
    if euid() != 0:
        raise TapError("the capture needs root: sudo tvgw experiment-tap")
    os.makedirs(run_dir, mode=0o700, exist_ok=True)
    os.chmod(run_dir, 0o700)
    try:
        mounts = read("/proc/self/mounts")
    except OSError:
        mounts = ""  # no mount table: nothing says the directory is memory
    if not on_tmpfs(os.path.realpath(run_dir), mounts):
        raise TapError(f"{run_dir} is not on tmpfs, so the capture would reach a disk")
    lock = os.open(run_dir, os.O_RDONLY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock)  # and the other run's capture is left alone: it deletes its own
        raise TapError("another run of the tap is capturing") from None
    path = os.path.join(run_dir, CAPTURE)
    handlers = {}
    try:
        handlers = {sig: signal.signal(sig, _stop) for sig in STOPS}
        free = os.statvfs(run_dir)
        argv = dumpcap_argv(dumpcap, tv_if, tv_ip, minutes, size_stop(free.f_bavail * free.f_frsize), path)
        before, cpu, start = _counter(read, tv_if), _children_cpu(), clock()
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
        except OSError as e:
            raise TapError(f"dumpcap could not start: {e.strerror}") from None
        try:
            _, err = proc.communicate()
        finally:
            if proc.poll() is None:  # a signal or Ctrl-C ended the wait: dumpcap stops too
                proc.terminate()
                proc.wait()
        seconds, after = clock() - start, _counter(read, tv_if)
        if proc.returncode != 0:
            said = (err.strip() or "no message").splitlines()[-1]
            raise TapError(f"dumpcap failed (exit {proc.returncode}): {said}")
        cpu_capture, rebuild = _children_cpu() - cpu, cpu_time()
        counts = msgtap.Counts()
        try:
            with open(path, "rb") as fh:
                totals, uploads = tally(msgtap.assemble(msgtap.read_pcap(fh, counts), counts))
        except (OSError, ValueError) as e:
            raise TapError(f"the capture could not be read: {e}") from None
        flags = msgtap.cadence(uploads)
        dropped = DROPPED.search(err)
        return Result(
            seconds=seconds,
            rows=rows(totals, flags, names(conn, totals)),
            counts=counts,
            received=after - before if before is not None and after is not None else None,
            dropped=int(dropped.group(1)) if dropped else None,
            cpu_capture=cpu_capture,
            cpu_rebuild=cpu_time() - rebuild,
        )
    finally:
        # a second signal, Ctrl-C's too, waits for the deletion
        held = signal.pthread_sigmask(signal.SIG_BLOCK, (*STOPS, signal.SIGINT))
        try:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            os.close(lock)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, held)
