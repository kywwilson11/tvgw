"""A plain UDP DNS question to a given server, decoded with `dnsmsg`. Used by `tvgw verify`, the
AdGuard readiness wait and the hardware tests; no resolver library needed.

(edges) Only the server's answer to this question is taken (design decision 108). The socket is
connected, so the kernel passes up only datagrams from the server's address and port; the question
carries a random id; and a datagram that is not a response with that id and that question is read past,
never taken as the answer and never as a failure, so a device that sprays the gateway's ports can
neither make a check pass nor make a resolver that answers look down.
"""

from __future__ import annotations

import secrets
import socket
import struct
import time

from tvgw import dnsmsg


def question(name: str, qtype: int = 1, qid: int | None = None) -> bytes:
    qid = secrets.randbits(16) if qid is None else qid
    labels = b"".join(bytes([len(x)]) + x.encode("idna") for x in name.rstrip(".").split("."))
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", qtype, 1)


def answers(asked: bytes, data: bytes) -> bool:
    """Whether `data` is a response to the question `asked`: its id, the response bit, and the question
    echoed, the name in any letter case (a resolver may echo the case it sent upstream)."""
    name = asked[12:-4]
    end = 12 + len(name)
    return (
        len(data) >= end + 4
        and data[:2] == asked[:2]
        and bool(data[2] & 0x80)
        and data[12:end].lower() == name.lower()
        and data[end : end + 4] == asked[-4:]
    )


def query(name: str, server: str = "127.0.0.1", timeout: float = 4.0, port: int = 53) -> bytes | None:
    """The server's raw response to a question for `name`, or None when none came within `timeout`
    seconds or the network failed. Any other datagram is read past within the same `timeout`."""
    asked = question(name)
    deadline = time.monotonic() + timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((server, port))
        sock.send(asked)
        while (left := deadline - time.monotonic()) > 0:
            sock.settimeout(left)
            data = sock.recv(4096)
            if answers(asked, data):
                return data
        return None
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
