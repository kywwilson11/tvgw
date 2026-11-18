"""dnsq, the gateway's own DNS question: only the server's answer to the question it asked is taken
(design decision 108). The server is a UDP socket on 127.0.0.1 that answers with a script of datagrams."""

import socket
import struct
import threading
import time
from collections.abc import Callable

import pytest

from tvgw import dnsq

ANSWER, FORGED = "192.0.2.7", "0.0.0.0"  # the server's, and what reads as "blocked by AdGuard"


def reply(
    asked: bytes, qid: bytes | None = None, flags: int = 0x8180, echoed: bytes | None = None, ip: str = ANSWER
) -> bytes:
    """A response to `asked` with one A record, `ip`; each other argument given spoils one part of it."""
    head = (asked[:2] if qid is None else qid) + struct.pack(">HHHHH", flags, 1, 1, 0, 0)
    record = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
    return head + (asked[12:] if echoed is None else echoed) + record


def serve(script: Callable[[bytes], list[tuple[bool, bytes]]], after: float = 0.0) -> int:
    """The port of a server that reads one question and, `after` seconds later, sends `script(question)`
    in order: each (from the server's own socket, datagram), or from another socket when the flag is
    False."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)

    def run() -> None:
        with srv:
            asked, client = srv.recvfrom(4096)
            time.sleep(after)
            for own, data in script(asked):
                if own:
                    srv.sendto(data, client)
                    continue
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
                    other.bind(("127.0.0.1", 0))
                    other.sendto(data, client)
                time.sleep(0.05)  # the kernel drops it on the connected socket before the next one

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


# each a datagram no answer to the question may be taken from, as section D of the lane's repro sent one
SPOILED = {
    "another id": lambda q: (True, reply(q, qid=bytes([q[0] ^ 0xFF, q[1]]), ip=FORGED)),
    "another question": lambda q: (
        True,
        reply(q, echoed=dnsq.question("mist-allow.example")[12:], ip=FORGED),
    ),
    "another type": lambda q: (
        True,
        reply(q, echoed=dnsq.question("must-allow.example", 28)[12:], ip=FORGED),
    ),
    "a question, not a response": lambda q: (True, reply(q, flags=0x0100, ip=FORGED)),
    "cut short": lambda q: (True, reply(q)[: len(q) - 1]),
    "two bytes": lambda q: (True, q[:2]),
    "from another port": lambda q: (False, reply(q, ip=FORGED)),
}


@pytest.mark.parametrize("spoiled", SPOILED.values(), ids=SPOILED.keys())
def test_a_late_right_answer_after_a_wrong_one_is_the_answer(spoiled):
    """The socket was not connected and the reply's id and question were never compared: whatever
    datagram came first was the answer, so a forged 0.0.0.0 read as "blocked by AdGuard" and a forged
    error as a resolver that does not answer. A wrong datagram is now read past, never a failure."""
    port = serve(lambda q: [spoiled(q), (True, reply(q))])
    data = dnsq.query("must-allow.example", "127.0.0.1", 3.0, port)
    assert data is not None and socket.inet_ntoa(data[-4:]) == ANSWER


@pytest.mark.parametrize("spoiled", SPOILED.values(), ids=SPOILED.keys())
def test_a_wrong_datagram_alone_is_no_answer(spoiled):
    port = serve(lambda q: [spoiled(q)])
    assert dnsq.query("must-allow.example", "127.0.0.1", 0.5, port) is None


def test_the_name_may_come_back_in_another_letter_case():
    port = serve(lambda q: [(True, reply(q, echoed=q[12:-4].upper() + q[-4:]))])
    assert dnsq.query("Must-Allow.example", "127.0.0.1", 3.0, port) is not None


def test_a_wrong_datagram_late_in_the_wait_does_not_lengthen_it():
    """Each read waits only what is left of the one timeout, however many wrong datagrams come."""
    port = serve(lambda q: [SPOILED["another id"](q)], after=0.8)
    started = time.monotonic()
    assert dnsq.query("must-allow.example", "127.0.0.1", 1.0, port) is None
    assert time.monotonic() - started < 1.5  # a fresh timeout per read would wait until 1.8 s


def test_a_closed_port_is_no_answer_at_once():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # bound, then closed: nothing listens on it
    started = time.monotonic()
    assert dnsq.query("must-allow.example", "127.0.0.1", 3.0, port) is None
    assert time.monotonic() - started < 1


def test_each_question_carries_its_own_id():
    """The id was the process id: anyone who could guess the process could forge the answer."""
    assert len({dnsq.question("must-allow.example")[:2] for _ in range(32)}) > 16
    assert dnsq.question("must-allow.example", qid=0x1234)[:2] == b"\x12\x34"
