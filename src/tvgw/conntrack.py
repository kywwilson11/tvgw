"""Parse `conntrack -E -e DESTROY -o timestamp,extended` lines into flows.

    [1792977952.120409]	[DESTROY] ipv4     2 tcp      6 TIME_WAIT src=10.10.10.17 dst=142.251.219.1
    sport=58998 dport=443 packets=18 bytes=2259 src=142.251.219.1 dst=192.0.2.48 sport=443
    dport=58998 packets=23 bytes=10742 [ASSURED] delta-time=360

The first src/dst/.../bytes tuple is the original direction (TV -> world = upload), the second the
reply (download). UDP and ICMP have no state word; ICMP has no ports. An entry the kernel destroyed
before its timer ran out (a reused tuple, a NAT clean-up, a flush) carries the seconds it had left
ahead of the state word, 'tcp 6 7417 ESTABLISHED src=...', kept as `timeout_left`; the connection
often goes on as a new entry that never saw a SYN.

Times. conntrack prints the DESTROY when the kernel expires the entry, one idle timeout after its
last packet: 120 s in TIME_WAIT (a normal close), 7440 s for an ESTABLISHED connection that went
quiet (tvgw-apply sets it), 30 or 120 s for UDP, plus up to about a minute of garbage-collector lag;
an entry destroyed early ends when it was destroyed, `timeout_left` short of that.
t_end is that moment, read from the line's timestamp, so it runs late by the timeout; t_start =
t_end - delta-time is within about a minute of the first packet. Nothing here corrects for the
timeout: a report that buckets by t_end credits a connection to the hour it expired, not the hour
it was used.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

FLOW_KEYS = ("src", "dst", "sport", "dport", "packets", "bytes")


@dataclass(frozen=True)
class Flow:
    t_start: float  # t_end - delta-time: within about a minute of the first packet
    t_end: float  # when the kernel expired the entry: last packet, plus the idle timeout, plus GC lag
    proto: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    pkts_up: int
    bytes_up: int
    pkts_down: int
    bytes_down: int
    state: str | None
    timeout_left: int | None = None  # seconds left on its timer when destroyed early; None: it expired


def parse_flow(line: str) -> Flow | None:
    toks = line.split()
    if len(toks) < 6 or not toks[0].startswith("[") or "[DESTROY]" not in toks:
        return None
    try:
        end = float(toks[0].strip("[]"))
        fam = next(i for i, t in enumerate(toks) if t in ("ipv4", "ipv6"))
        proto = toks[fam + 2]
    except (ValueError, StopIteration, IndexError):
        return None
    if not math.isfinite(end):  # float() accepts "nan" and "inf"; SQLite binds them as NULL
        return None
    orig: dict[str, str] = {}
    reply: dict[str, str] = {}
    extra: dict[str, str] = {}
    state = ""
    cur = orig
    rest = toks[fam + 4 :]
    left = None
    if rest and rest[0].isascii() and rest[0].isdigit():  # destroyed early: the time it had left
        left = int(rest.pop(0))
        if left >= 1 << 63:
            raise ValueError(f"a timeout of {left} s does not fit a 64-bit integer")
    for t in rest:
        if t.startswith("[") and t.endswith("]"):
            continue  # ASSURED, UNREPLIED
        k, eq, v = t.partition("=")
        if not eq:
            state = state or t  # ESTABLISHED, TIME_WAIT, ...
            continue
        if k == "src" and cur is orig and "src" in orig:
            cur = reply
        if k in FLOW_KEYS and k not in cur:
            cur[k] = v
        else:
            extra.setdefault(k, v)  # delta-time, id, mark, zone
    if "src" not in orig or "dst" not in orig:
        return None

    def num(d: dict[str, str], k: str) -> int:
        """A counter: 0 when absent or not a number (str.isdigit is true for '²', which int() rejects).
        A value SQLite cannot store is the caller's to count as malformed, not to poison a batch with."""
        v = d.get(k, "")
        if not (v.isascii() and v.isdigit()):
            return 0
        n = int(v)
        if n >= 1 << 63:
            raise ValueError(f"{k}={v} does not fit a 64-bit counter")
        return n

    try:
        dur = float(extra.get("delta-time", "0"))
    except ValueError:
        dur = 0.0
    if not 0.0 <= dur <= end:  # nan, inf, negative, or longer than the epoch: a zero-length flow
        dur = 0.0
    return Flow(
        t_start=end - dur,
        t_end=end,
        proto=proto,
        src=orig["src"],
        dst=orig["dst"],
        sport=num(orig, "sport") or None,
        dport=num(orig, "dport") or None,
        pkts_up=num(orig, "packets"),
        bytes_up=num(orig, "bytes"),
        pkts_down=num(reply, "packets"),
        bytes_down=num(reply, "bytes"),
        state=state or None,
        timeout_left=left,
    )
