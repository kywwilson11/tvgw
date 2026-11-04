"""(lists) The virtual suite's DNS probe (tests/virtual/dnsprobe.py) without root: the question it
sends and how it reads the three answers the strip test judges, from hand-built messages."""

from __future__ import annotations

import json
import socket
import struct
import subprocess
import sys
import threading

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "tests" / "virtual"))

import dnsprobe  # after the insert: tests/virtual is not on the path otherwise

SOA = (
    b"\xc0\x0c"
    + struct.pack(">HHIH", 6, 1, 900, 22)
    + b"\x00\x00"  # mname, rname: the root, compressed to nothing
    + struct.pack(">IIIII", 1, 1800, 900, 604800, 86400)
)


def reply(
    q: bytes, flags: int, answers: bytes = b"", an: int = 0, authority: bytes = b"", ns: int = 0
) -> bytes:
    return q[:2] + struct.pack(">HHHHH", flags, 1, an, ns, 0) + q[12:] + answers + authority


def test_the_question_names_the_type_and_asks_for_recursion():
    q = dnsprobe.question("crypto.example.com", dnsprobe.TYPES["HTTPS"], qid=7)
    assert q[:4] == b"\x00\x07\x01\x00"
    assert q[12:] == b"\x06crypto\x07example\x03com\x00" + struct.pack(">HH", 65, 1)


def test_an_empty_noerror_without_soa():
    q = dnsprobe.question("crypto.example.com", 65)
    assert dnsprobe.summary(reply(q, 0x8180)) == {
        "rcode": 0,
        "counts": [1, 0, 0, 0],
        "answer": [],
        "authority": [],
        "addresses": [],
    }


def test_nodata_carries_its_soa():
    q = dnsprobe.question("svc.example.com", 64)
    got = dnsprobe.summary(reply(q, 0x8180, authority=SOA, ns=1))
    assert got["rcode"] == 0 and got["answer"] == [] and got["authority"] == [6]


def test_a_blocked_a_answer_reads_as_its_address():
    q = dnsprobe.question("tracker.example.com", 1)
    a = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 10, 4) + bytes(4)
    got = dnsprobe.summary(reply(q, 0x8180, answers=a, an=1))
    assert got["answer"] == [1] and got["addresses"] == ["0.0.0.0"]


def test_a_short_message_is_refused():
    with pytest.raises(ValueError):
        dnsprobe.summary(b"\x00\x01")


def test_the_script_prints_the_summary_of_a_real_exchange():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)
    port = sock.getsockname()[1]

    def serve():
        q, peer = sock.recvfrom(512)
        sock.sendto(reply(q, 0x8180, authority=SOA, ns=1), peer)

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    code = f"import dnsprobe, json; print(json.dumps(dnsprobe.ask('127.0.0.1', 'SVCB', 'svc.example.com', port={port})))"
    out = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            f"import sys; sys.path.insert(0, {str(ROOT / 'tests' / 'virtual')!r}); {code}",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
    )
    t.join(timeout=5)
    sock.close()
    assert json.loads(out.stdout)["authority"] == [6], out.stderr
