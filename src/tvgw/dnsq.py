"""A plain UDP DNS question to a given server, decoded with `dnsmsg`. Used by `tvgw verify`, the
AdGuard readiness wait and the hardware tests; no resolver library needed."""

from __future__ import annotations

import os
import socket
import struct

from tvgw import dnsmsg


def question(name: str, qtype: int = 1, qid: int | None = None) -> bytes:
    qid = (os.getpid() & 0xFFFF) if qid is None else qid
    labels = b"".join(bytes([len(x)]) + x.encode("idna") for x in name.rstrip(".").split("."))
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def query(name: str, server: str = "127.0.0.1", timeout: float = 4.0, port: int = 53) -> bytes | None:
    """The raw response, or None on timeout / network error."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(question(name), (server, port))
        data, _ = sock.recvfrom(4096)
        return data
    except OSError:
        return None
    finally:
        sock.close()


def a_records(name: str, server: str = "127.0.0.1", timeout: float = 4.0) -> list[str] | None:
    """A records from `server` (['0.0.0.0'] means blocked by AdGuard), [] for a negative answer,
    None when the server did not answer at all."""
    data = query(name, server, timeout)
    if data is None:
        return None
    try:
        return [a.value for a in dnsmsg.decode_answers(data) if a.rtype == "A"]
    except (ValueError, IndexError, struct.error):
        return []
