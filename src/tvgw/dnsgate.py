"""DNS-gated egress, the count-only phase: feed `inet tvgw_gate resolved4` with every IPv4 address
the resolver hands the TV.

tcpdump streams the resolver's answers to the TV (UDP from the gateway's port 53) as a pcap stream
on stdout; each DNS message is decoded with the store's own decoder and its A records are added to
the set with a one-day timeout. The firewall then counts, and logs a sample of, every new connection
the TV opens to an address the set does not hold: a hardcoded server or a resolver bypass. `add` is
idempotent, so an address resolved again keeps its first expiry; the TV re-resolves before it
reconnects, so a lookup always precedes a legitimate connection, and the first day after a reboot
is the only time the count overstates (the TV's cache outlives the Pi's).

Everything that parses bytes is a pure function; the loop takes its processes as parameters.
"""

from __future__ import annotations

import ipaddress
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Iterator

from tvgw import dnsmsg
from tvgw.config import Settings

TABLE, SET = "inet tvgw_gate", "resolved4"
TTL = 86400  # seconds an address stays in the set; a day, however short the record's TTL
MAGICS = {  # pcap file magic -> struct byte order; microsecond and nanosecond variants
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
LINKTYPE_ETHERNET = 1


class StreamEnded(RuntimeError):
    pass


def _exactly(read: Callable[[int], bytes], n: int, boundary: bool = False) -> bytes | None:
    """`n` bytes, or None at a clean end of stream when `boundary` (nothing read yet); an end inside
    a record or header raises StreamEnded."""
    buf = b""
    while len(buf) < n:
        chunk = read(n - len(buf))
        if not chunk:
            if boundary and not buf:
                return None
            raise StreamEnded("capture stream ended mid-record")
        buf += chunk
    return buf


def pcap_records(read: Callable[[int], bytes]) -> Iterator[bytes]:
    """Frames from a pcap stream (`tcpdump -w -`), checking the magic and the link type first."""
    head = _exactly(read, 24, boundary=True)
    if head is None:
        return
    order = MAGICS.get(head[:4])
    if order is None:
        raise RuntimeError(f"not a pcap stream (magic {head[:4].hex()})")
    linktype = struct.unpack(order + "I", head[20:24])[0]
    if linktype != LINKTYPE_ETHERNET:
        raise RuntimeError(f"link type {linktype} is not Ethernet")
    while (rec := _exactly(read, 16, boundary=True)) is not None:
        _, _, incl, _ = struct.unpack(order + "IIII", rec)
        if incl > 262144:
            raise RuntimeError(f"absurd record length {incl}")
        yield _exactly(read, incl)


def udp_payload(frame: bytes) -> bytes | None:
    """The UDP payload of an Ethernet/IPv4 frame (one VLAN tag allowed); None for anything else,
    including fragments after the first."""
    if len(frame) < 14:
        return None
    off = 12
    ethertype = struct.unpack(">H", frame[off : off + 2])[0]
    off += 2
    if ethertype == 0x8100:
        if len(frame) < off + 4:
            return None
        ethertype = struct.unpack(">H", frame[off + 2 : off + 4])[0]
        off += 4
    if ethertype != 0x0800 or len(frame) < off + 20:
        return None
    ihl = (frame[off] & 0x0F) * 4
    if ihl < 20 or frame[off + 9] != 17 or len(frame) < off + ihl + 8:
        return None
    flags_frag = struct.unpack(">H", frame[off + 6 : off + 8])[0]
    if flags_frag & 0x1FFF:
        return None
    total = struct.unpack(">H", frame[off + 2 : off + 4])[0]
    end = min(len(frame), off + total)
    return frame[off + ihl + 8 : end]


def addresses(message: bytes) -> list[str]:
    """The IPv4 addresses a DNS response hands out, in order, without repeats; 0.0.0.0 (a blocked
    answer) and other unroutable values are not addresses the TV can reach."""
    try:
        answers = dnsmsg.decode_answers(message)
    except dnsmsg.DnsFormatError:
        return []
    out: list[str] = []
    for a in answers:
        if a.rtype != "A" or a.value in out:
            continue
        try:
            ip = ipaddress.IPv4Address(a.value)
        except ValueError:
            continue
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_reserved:
            continue
        out.append(a.value)
    return out


def batch(ips: list[str], ttl: int = TTL) -> str:
    """The nft script that adds `ips` to the set with the gate's timeout."""
    return f"add element {TABLE} {SET} {{ {', '.join(f'{ip} timeout {ttl}s' for ip in ips)} }}\n"


def tcpdump_argv(s: Settings) -> list[str]:
    # the resolver's answers to the TV, and nothing else: no snapshot limit (answers can be large)
    return [
        "tcpdump", "-i", s.tv_if, "-n", "-U", "-s", "0", "-w", "-",
        "udp", "and", "src", "host", s.gw_ip, "and", "src", "port", "53", "and", "dst", "host", s.tv_ip,
    ]  # fmt: skip


def feed(
    read: Callable[[int], bytes],
    nft: Callable[[str], int],
    log: Callable[[str], None] = lambda line: print(line, file=sys.stderr, flush=True),
    clock: Callable[[], float] = time.time,
) -> int:
    """Consume the stream until it ends; returns the number of addresses added. An nft failure is
    logged at most once a minute and the loop goes on: the table may be gone for a moment during a
    re-apply, and the next answer will try again."""
    added, last_err = 0, 0.0
    for frame in pcap_records(read):
        payload = udp_payload(frame)
        if not payload:
            continue
        ips = addresses(payload)
        if not ips:
            continue
        if nft(batch(ips)) == 0:
            added += len(ips)
        elif (now := clock()) - last_err > 60:
            last_err = now
            log(f"tvgw dnsgate: nft refused {len(ips)} address(es); is {TABLE} loaded?")
    return added


def _nft(script: str) -> int:
    return subprocess.run(
        ["nft", "-f", "-"], input=script.encode(), capture_output=True, timeout=30
    ).returncode


def main(s: Settings) -> int:
    if s.dnsgate == "off":
        print("tvgw dnsgate: DNSGATE=off, nothing to feed", flush=True)
        return 0
    proc = subprocess.Popen(tcpdump_argv(s), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert proc.stdout is not None
    print(f"tvgw dnsgate: feeding {TABLE} {SET} from {s.tv_if} ({s.gw_ip}:53 -> {s.tv_ip})", flush=True)
    try:
        feed(proc.stdout.read, _nft)  # returns only when the stream ends: tcpdump is gone
    except StreamEnded:
        pass
    finally:
        proc.kill()
        proc.wait()
    print(f"tvgw dnsgate: tcpdump ended (rc={proc.returncode})", file=sys.stderr, flush=True)
    return 1
