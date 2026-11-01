"""(lists) One DNS question over UDP, and the shape of the answer as JSON: the response code, the record
types in the answer and authority sections. Standard library only, run with `python -I` inside a
namespace, so the virtual suite can ask the real AdGuard Home what it tells the TV.

    python3 -I dnsprobe.py SERVER TYPE NAME     ->  {"rcode": 0, "answer": [], "authority": [6], ...}

The pure parts (question(), summary()) are unit-tested in tests/unit/test_virtual_dnsprobe.py."""

from __future__ import annotations

import json
import os
import socket
import struct
import sys

TYPES = {"A": 1, "SOA": 6, "AAAA": 28, "SVCB": 64, "HTTPS": 65}
A_TYPE = TYPES["A"]


def question(name: str, qtype: int, qid: int = 0x7476) -> bytes:
    """A recursion-desired query for one name and type, class IN."""
    labels = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.rstrip(".").split(".") if x)
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def _skip_name(msg: bytes, off: int) -> int:
    """The offset after the (possibly compressed) name at `off`."""
    while True:
        if off >= len(msg):
            raise ValueError("truncated name")
        n = msg[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += 1 + n


def summary(msg: bytes) -> dict:
    """rcode, the section counts, the type of every answer and authority record, and the A addresses."""
    if len(msg) < 12:
        raise ValueError("short header")
    _qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
    off = 12
    for _ in range(qd):
        off = _skip_name(msg, off) + 4
    sections: list[list[int]] = [[], []]
    addresses: list[str] = []
    for i, count in enumerate((an, ns)):
        for _ in range(count):
            off = _skip_name(msg, off)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[off : off + 10])
            off += 10
            if i == 0 and rtype == A_TYPE and rdlen == 4:
                addresses.append(".".join(str(b) for b in msg[off : off + 4]))
            sections[i].append(rtype)
            off += rdlen
    return {
        "rcode": flags & 0x0F,
        "counts": [qd, an, ns, ar],
        "answer": sections[0],
        "authority": sections[1],
        "addresses": addresses,
    }


def ask(server: str, qtype: str, name: str, port: int = 53, timeout: float = 3.0) -> dict | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(question(name, TYPES[qtype], os.getpid() & 0xFFFF), (server, port))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()
    return summary(data)


def main(argv: list[str]) -> int:
    server, qtype, name = argv
    print(json.dumps(ask(server, qtype, name)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
