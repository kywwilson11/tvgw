"""The capture filter, compiled and run by tcpdump on a synthetic hour: exactly the frames the TV sends
that the analysis reads, and nothing the TV receives."""

import random
import re
import shutil
import socket
import struct
import subprocess

import pytest
from conftest import capture_argv

pytestmark = pytest.mark.skipif(shutil.which("tcpdump") is None, reason="tcpdump compiles the filter")

TV, GW, SERVER, LAN, MCAST = "10.10.10.17", "10.10.10.1", "203.0.113.10", "192.168.8.69", "239.255.255.250"
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
rng = random.Random(2026)  # seeded: the random segments are the same on every run


def frame(src: str, dst: str, proto: int, l4: bytes) -> bytes:
    """Ethernet with zero MACs (not an address) and IPv4; checksums stay zero, filters never read them."""
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(l4),
        0,
        0,
        64,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return bytes(12) + b"\x08\x00" + ip + l4


def tcp(src: str, sport: int, dst: str, dport: int, flags: int, payload: bytes = b"") -> bytes:
    return frame(
        src, dst, 6, struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    )


def udp(src: str, sport: int, dst: str, dport: int, payload: bytes) -> bytes:
    return frame(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


def pcap(frames) -> bytes:
    """Frame n is stamped at n seconds, so `tcpdump -tt` prints the frame number back for each kept frame
    (`-#` would number the kept frames, not the original ones)."""
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # link type 1: Ethernet
    return header + b"".join(struct.pack("<IIII", n, 0, len(f), len(f)) + f for n, f in enumerate(frames, 1))


def scenario() -> list[tuple[bool, bytes]]:
    """(kept, frame) in capture order: one of everything the wire carries in an hour."""
    hello = bytes([0x16, 0x03, 0x01, 0x01, 0x27, 0x01, 0x00, 0x01, 0x23, 0x03, 0x03]) + rng.randbytes(289)
    dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03foo\x03com\x00\x00\x01\x00\x01"
    return [
        (True, tcp(TV, 40000, SERVER, 443, SYN)),
        (False, tcp(SERVER, 443, TV, 40000, SYN | ACK)),
        (False, tcp(TV, 40000, SERVER, 443, ACK)),
        (True, tcp(TV, 40001, GW, 80, ACK)),  # no payload: must match on the port before any payload load
        (True, tcp(TV, 40000, SERVER, 443, PSH | ACK, hello)),
        (False, tcp(TV, 40000, SERVER, 443, PSH | ACK, b"\x00" + rng.randbytes(399))),  # hello continuation
        (False, tcp(TV, 40000, SERVER, 443, PSH | ACK, b"\x16\x03\x01")),  # too short to hold a type byte
        (
            False,
            tcp(
                SERVER,
                443,
                TV,
                40000,
                PSH | ACK,
                bytes([0x16, 0x03, 0x03, 0, 0x40, 0x02]) + rng.randbytes(60),
            ),
        ),
        (False, tcp(SERVER, 443, TV, 40000, PSH | ACK, b"\x16\x9a" + rng.randbytes(1398))),  # mid-record
        (False, tcp(SERVER, 443, TV, 40000, PSH | ACK, b"\x17\x03\x03\x00\x20" + rng.randbytes(32))),
        (
            False,
            tcp(
                TV, 40000, SERVER, 443, PSH | ACK, bytes([0x16, 0x03, 0x03, 0x01, 0, 0]) + rng.randbytes(100)
            ),
        ),
        (
            True,
            tcp(
                TV,
                40001,
                GW,
                80,
                PSH | ACK,
                b"GET /fts/x?biz_code=APP_STORE HTTP/1.1\r\nHost: ngfts.lge.com\r\n\r\n",
            ),
        ),
        (True, tcp(TV, 40001, GW, 80, PSH | ACK, rng.randbytes(600))),  # a request body: still to port 80
        (False, tcp(GW, 80, TV, 40001, PSH | ACK, b"HTTP/1.1 200 OK\r\nContent-Length: 1400\r\n\r\n")),
        (False, tcp(GW, 80, TV, 40001, PSH | ACK, rng.randbytes(1400))),  # the response body
        (True, tcp(TV, 40002, SERVER, 8080, PSH | ACK, b"GET /firmware HTTP/1.1\r\nHost: x\r\n\r\n")),
        (True, tcp(TV, 40002, SERVER, 8080, PSH | ACK, b"POST /report HTTP/1.1\r\nHost: x\r\n\r\n")),
        (True, tcp(TV, 40000, SERVER, 443, FIN | ACK)),
        (False, tcp(SERVER, 443, TV, 40000, FIN | PSH | ACK, rng.randbytes(1400))),
        (False, tcp(SERVER, 443, TV, 40000, RST)),
        (True, udp(TV, 50000, "8.8.8.8", 53, dns_query)),  # the hardcoded resolver: still the TV's frame
        (
            False,
            udp(
                GW,
                53,
                TV,
                50000,
                dns_query + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04",
            ),
        ),
        (True, udp(TV, 50001, SERVER, 443, b"\xc3" + rng.randbytes(1199))),  # QUIC Initial: long header
        (False, udp(TV, 50001, SERVER, 443, b"\x40" + rng.randbytes(40))),  # QUIC short header
        (True, udp(TV, 50002, MCAST, 1900, b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n")),
        (True, tcp(TV, 40003, LAN, 80, SYN)),  # a LAN probe: dropped by the firewall, kept as evidence
        (False, tcp(GW, 40004, TV, 3000, SYN)),
        (True, udp(TV, 50003, SERVER, 5000, rng.randbytes(1400))),  # an unexpected port: whole, like today
    ]


def test_filter_keeps_what_the_tv_sends_and_the_analysis_reads(tmp_path):
    rows = scenario()
    rows += [(False, tcp(SERVER, 443, TV, 40000, PSH | ACK, rng.randbytes(1448))) for _ in range(2000)]
    rows += [(False, tcp(TV, 40000, SERVER, 443, PSH | ACK, rng.randbytes(1448))) for _ in range(2000)]
    path = tmp_path / "tv.pcap"
    path.write_bytes(pcap(f for _, f in rows))
    argv = capture_argv()
    out = subprocess.run(
        ["tcpdump", "-tt", "-nr", str(path), *argv[argv.index("-w") + 2 :]],
        capture_output=True,
        text=True,
        timeout=120,
    )
    noise = [ln for ln in out.stderr.splitlines() if not ln.startswith("reading from file")]
    assert out.returncode == 0 and noise == [], out.stderr  # a filter tcpdump rejects would stop the capture
    kept = {int(m.group(1)) for m in re.finditer(r"^(\d+)\.\d+ ", out.stdout, re.MULTILINE)}
    assert kept == {n for n, (keep, _) in enumerate(rows, 1) if keep}
