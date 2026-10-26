"""Decode the answer section of a raw DNS message (RFC 1035), as AdGuard stores it base64-encoded.

Only what the gateway needs: A, AAAA and CNAME records, with name compression handled.
"""

from __future__ import annotations

import base64
import struct
from dataclasses import dataclass

TYPE_A, TYPE_CNAME, TYPE_AAAA = 1, 5, 28
_TYPE_NAMES = {TYPE_A: "A", TYPE_CNAME: "CNAME", TYPE_AAAA: "AAAA"}


@dataclass(frozen=True)
class Answer:
    rtype: str
    value: str
    ttl: int


class DnsFormatError(ValueError):
    pass


def read_name(msg: bytes, off: int) -> tuple[str, int]:
    """Return (dotted name, offset after the name as it appears at `off`)."""
    labels: list[str] = []
    end = None
    hops = 0
    while True:
        if off >= len(msg):
            raise DnsFormatError("truncated name")
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise DnsFormatError("truncated pointer")
            ptr = struct.unpack(">H", msg[off : off + 2])[0] & 0x3FFF
            if end is None:
                end = off + 2
            hops += 1
            if hops > 64 or ptr >= off:
                raise DnsFormatError("pointer loop")
            off = ptr
            continue
        labels.append(msg[off + 1 : off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), (end if end is not None else off)


def decode_answers(message: bytes | str) -> list[Answer]:
    """A/AAAA/CNAME answers of a DNS message (bytes or base64 text). Other types are skipped."""
    msg = base64.b64decode(message) if isinstance(message, str) else message
    if len(msg) < 12:
        raise DnsFormatError("short header")
    qd, an = struct.unpack(">HH", msg[4:8])
    off = 12
    for _ in range(qd):
        _, off = read_name(msg, off)
        off += 4
    out: list[Answer] = []
    for _ in range(an):
        _, off = read_name(msg, off)
        if off + 10 > len(msg):
            raise DnsFormatError("truncated record")
        rtype, _, ttl, rdlen = struct.unpack(">HHIH", msg[off : off + 10])
        off += 10
        rd = msg[off : off + rdlen]
        if len(rd) != rdlen:
            raise DnsFormatError("truncated rdata")
        if rtype == TYPE_A and rdlen == 4:
            out.append(Answer("A", ".".join(str(b) for b in rd), ttl))
        elif rtype == TYPE_AAAA and rdlen == 16:
            out.append(
                Answer("AAAA", ":".join(f"{(rd[i] << 8) | rd[i + 1]:x}" for i in range(0, 16, 2)), ttl)
            )
        elif rtype == TYPE_CNAME:
            out.append(Answer("CNAME", read_name(msg, off)[0], ttl))
        off += rdlen
    return out


def answers_text(message: bytes | str) -> str | None:
    """'A:1.2.3.4,CNAME:x.y' for storage; None when the message can't be decoded."""
    try:
        return ",".join(f"{a.rtype}:{a.value}" for a in decode_answers(message))
    except (DnsFormatError, struct.error, ValueError):
        return None


def is_blocked_answer(answers: list[Answer]) -> bool:
    """AdGuard answers blocked names with 0.0.0.0 / :: in its default blocking mode."""
    addrs = [a for a in answers if a.rtype in ("A", "AAAA")]
    return bool(addrs) and all(a.value in ("0.0.0.0", "0:0:0:0:0:0:0:0") for a in addrs)
