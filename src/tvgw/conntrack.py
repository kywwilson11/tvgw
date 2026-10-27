"""Parse `conntrack -E -e DESTROY -o timestamp,extended` lines into flows.

    [1792977952.120409]	[DESTROY] ipv4     2 tcp      6 TIME_WAIT src=10.10.10.17 dst=142.251.219.1
    sport=58998 dport=443 packets=18 bytes=2259 src=142.251.219.1 dst=192.0.2.48 sport=443
    dport=58998 packets=23 bytes=10742 [ASSURED] delta-time=360

The first src/dst/.../bytes tuple is the original direction (TV -> world = upload), the second the
reply (download). UDP and ICMP have no state word; ICMP has no ports.
"""

from __future__ import annotations

from dataclasses import dataclass

FLOW_KEYS = ("src", "dst", "sport", "dport", "packets", "bytes")


@dataclass(frozen=True)
class Flow:
    t_start: float
    t_end: float
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
    orig: dict[str, str] = {}
    reply: dict[str, str] = {}
    extra: dict[str, str] = {}
    state = ""
    cur = orig
    for t in toks[fam + 4 :]:
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
        return int(d[k]) if d.get(k, "").isdigit() else 0

    try:
        dur = float(extra.get("delta-time", "0"))
    except ValueError:
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
    )
