"""(inpath) The DNS gate's in-path filler (design decision 64) without a kernel: what it reads out of a
queued packet, what it never lets into the set, when it holds an answer and when it lets go, and the
loop around it, each against fakes. The property under all of them: every packet handed over is
released exactly once, whatever its bytes are and whatever the add does.

The kernel's half (the queue rule, bypass, fail-open, the set's expiry) is tests/virtual's."""

import errno
import json
import random
import socket
import struct
import threading
import time

import pytest
from test_nfnl import ack_bytes

from tvgw import config, dnsgate, dnsmsg, inpath, nfnl

TV, GW = "10.10.10.17", "10.10.10.1"


def ip4(text: str) -> bytes:
    return bytes(int(x) for x in text.split("."))


def name(text: str) -> bytes:
    return b"".join(bytes([len(x)]) + x.encode("ascii") for x in text.split(".")) + b"\x00"


def dns(answers=(), flags=0x8180, qname="cdn.example", qd=1, an=None) -> bytes:
    """A DNS response: one question, then (type, rdata) answers, each owned by a pointer to the question."""
    msg = struct.pack(">HHHHHH", 0x1234, flags, qd, len(answers) if an is None else an, 0, 0)
    msg += (name(qname) + struct.pack(">HH", 1, 1)) * qd
    for rtype, rdata in answers:
        msg += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
    return msg


def a(text: str) -> tuple[int, bytes]:
    return 1, ip4(text)


def udp(payload: bytes, frag: int = 0, total: int | None = None, ihl: int = 5) -> bytes:
    """An IPv4/UDP packet from the gateway's port 53 to the TV, as the queue hands it over."""
    options = b"\x01" * ((ihl - 5) * 4)
    datagram = struct.pack(">HHHH", 53, 40000, 8 + len(payload), 0) + payload
    length = ihl * 4 + len(datagram) if total is None else total
    head = struct.pack(">BBHHHBBH4s4s", 0x40 | ihl, 0, length, 1, frag, 64, 17, 0, ip4(GW), ip4(TV))
    return head + options + datagram


def tcp(data: bytes, doff: int = 5, flags: int = 0x18) -> bytes:
    segment = struct.pack(">HHIIBBHHH", 53, 40000, 1, 1, doff << 4, flags, 1000, 0, 0)
    segment += b"\x01" * ((doff - 5) * 4) + data
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 1, 0x4000, 64, 6, 0, ip4(GW), ip4(TV))
    return head + segment


def framed(*messages: bytes) -> bytes:
    """DNS over TCP: each message after its two-byte length."""
    return b"".join(struct.pack(">H", len(m)) + m for m in messages)


ANSWER = dns([a("203.0.113.5"), a("203.0.113.6")])
# a real-shaped answer written out byte by byte: us.example CNAME edge.example, edge.example A 198.51.100.7
FIXED = bytes.fromhex(
    "4500005b000140004011"
    + "0000"
    + "0a0a0a01"
    + "0a0a0a11"  # IPv4, 91 bytes, UDP, 10.10.10.1 -> 10.10.10.17
    + "0035c35000470000"  # UDP 53 -> 50000, length 71
    + "abcd81800001000200000000"  # id, response, 1 question, 2 answers
    + "027573076578616d706c650000010001"  # us.example A IN
    + "c00c000500010000003c0007"
    + "0465646765c00f"  # CNAME edge.<example>
    + "c028000100010000003c0004"
    + "c6336407"  # A 198.51.100.7
)


# ---- what a queued packet is, and which addresses it may add -------------------------------------------


def test_a_udp_answer_gives_every_a_record_once_in_order():
    parsed = inpath.read_packet(udp(dns([a("203.0.113.5"), a("203.0.113.6"), a("203.0.113.5")])))
    assert parsed == inpath.Parsed(inpath.ANSWER, (ip4("203.0.113.5"), ip4("203.0.113.6")))
    assert inpath.read_packet(FIXED) == inpath.Parsed(inpath.ANSWER, (ip4("198.51.100.7"),))
    assert inpath.read_packet(udp(ANSWER, ihl=7)).addrs == (ip4("203.0.113.5"), ip4("203.0.113.6"))


def test_a_cname_chain_gives_every_a_record_of_the_answer():
    chain = dns(
        [
            (5, name("edge.cdn.example")),
            (5, b"\x02eu\xc0\x0c"),
            a("198.51.100.1"),
            a("198.51.100.2"),
            (28, bytes(16)),  # AAAA: the TV side has no IPv6
            a("198.51.100.3"),
        ]
    )
    assert inpath.read_packet(udp(chain)).addrs == tuple(ip4(f"198.51.100.{n}") for n in (1, 2, 3))


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",  # the blocked answer
        "0.1.2.3",
        "10.10.10.1",  # a rewrite to the gateway
        "10.20.30.40",
        "100.64.0.1",
        "100.127.255.254",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "224.0.0.251",
        "239.255.255.250",
        "240.0.0.1",
        "255.255.255.255",
    ],
)
def test_the_blocked_answer_and_every_non_global_address_stay_out(address):
    assert not inpath.admissible(ip4(address))
    parsed = inpath.read_packet(udp(dns([a(address)])))
    assert parsed == inpath.Parsed(inpath.ANSWER, ())
    mixed = inpath.read_packet(udp(dns([a(address), a("203.0.113.9")])))
    assert mixed.addrs == (ip4("203.0.113.9"),)


@pytest.mark.parametrize(
    "address",
    [
        "1.1.1.1",
        "9.255.255.255",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "126.255.255.255",
        "128.0.0.1",
        "169.253.0.1",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "223.255.255.255",
        "198.51.100.7",
        "203.0.113.5",
        "192.0.2.1",
    ],  # the documentation ranges: the namespace tier's internet
)
def test_the_edges_of_the_refused_ranges_are_let_in(address):
    assert inpath.admissible(ip4(address))


def test_admissible_refuses_anything_that_is_not_four_bytes():
    assert (
        not inpath.admissible(b"")
        and not inpath.admissible(bytes(16))
        and not inpath.admissible(b"\x01\x01\x01")
    )


def test_the_non_global_ranges_cover_what_the_firewall_calls_the_home_lan():
    """tvgw-apply's lan4 set is what the TV may never reach; an answer naming one of its addresses must
    not become an address DNS handed the TV."""
    from conftest import ROOT

    apply = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
    (elements,) = __import__("re").findall(r"set lan4 \{[^}]*elements = \{ ([^}]+) \}", apply)
    for net in elements.split(", "):
        base, bits = net.split("/")
        first = ip4(base)
        last = (int.from_bytes(first, "big") | ((1 << (32 - int(bits))) - 1)).to_bytes(4, "big")
        assert not inpath.admissible(first) and not inpath.admissible(last), net


def test_a_truncated_answer_passes_untouched():
    parsed = inpath.read_packet(udp(dns([a("203.0.113.5")], flags=0x8380)))
    assert parsed == inpath.Parsed(inpath.TRUNCATED)


def test_what_is_not_an_answer_is_other_and_never_read():
    assert inpath.read_packet(udp(dns([a("203.0.113.5")], flags=0x0100))).kind == inpath.OTHER  # a query
    assert inpath.read_packet(None).kind == inpath.OTHER  # the queue sent no payload
    assert inpath.read_packet(b"").kind == inpath.OTHER
    assert inpath.read_packet(b"\x60" + bytes(60)).kind == inpath.OTHER  # IPv6
    icmp = bytearray(udp(ANSWER))
    icmp[9] = 1
    assert inpath.read_packet(bytes(icmp)).kind == inpath.OTHER
    assert inpath.read_packet(tcp(b"")).kind == inpath.OTHER  # a bare ACK
    assert inpath.read_packet(tcp(framed(dns([a("203.0.113.5")], flags=0x8380)))).kind == inpath.OTHER


@pytest.mark.parametrize(
    "packet",
    [
        udp(ANSWER[:-2]),  # the last record cut
        udp(ANSWER[:11]),  # less than a header
        udp(dns([a("203.0.113.5")], an=3)),  # more answers promised than sent
        udp(ANSWER[:-6] + b"\x00\x09" + ANSWER[-4:]),  # a record length that runs past the end
        udp(ANSWER + bytes(inpath.MAX_DNS)),  # longer than the filler reads
        udp(ANSWER, frag=0x2000),  # more fragments follow
        udp(ANSWER, frag=0x0010),  # a later fragment
        udp(ANSWER, total=10),  # a total length shorter than the header
        udp(ANSWER, total=4000),  # a total length longer than the packet
        udp(b""),
        udp(b"\x00\x00\x80" + b"\xff" * 40),  # a response by its flags, noise after them
    ],
)
def test_a_udp_answer_that_does_not_read_is_unparsed_and_never_an_error(packet):
    assert inpath.read_packet(packet) == inpath.Parsed(inpath.UNPARSED_UDP)


def test_a_packet_the_queue_cut_is_unparsed():
    assert inpath.read_packet(udp(ANSWER), whole=False).kind == inpath.UNPARSED_UDP


def test_a_tcp_answer_whole_in_one_segment_is_read():
    one = inpath.read_packet(tcp(framed(ANSWER)))
    assert one == inpath.Parsed(inpath.ANSWER, (ip4("203.0.113.5"), ip4("203.0.113.6")))
    two = inpath.read_packet(tcp(framed(ANSWER, dns([a("198.51.100.1"), a("203.0.113.5")])), doff=8))
    assert two.addrs == (ip4("203.0.113.5"), ip4("203.0.113.6"), ip4("198.51.100.1"))


@pytest.mark.parametrize(
    "data",
    [
        framed(ANSWER)[:-1],  # the answer continues in the next segment
        framed(ANSWER)[5:],  # the rest of an answer that began earlier
        framed(ANSWER) + b"\x00",  # one byte of the next length
        framed(ANSWER) + b"\x00\x00",  # a message of no bytes
        b"\x00",
        framed(ANSWER[:-2]),  # whole by its length, malformed inside
        framed(*[ANSWER] * (inpath.TCP_MESSAGES + 1)),
    ],
)
def test_a_tcp_segment_that_is_not_whole_answers_passes_unparsed(data):
    assert inpath.read_packet(tcp(data)) == inpath.Parsed(inpath.UNPARSED_TCP)


def test_a_tcp_header_that_does_not_fit_is_unparsed():
    short = tcp(framed(ANSWER))[:30]
    fixed = bytearray(short)
    fixed[2:4] = struct.pack(">H", len(short))
    assert inpath.read_packet(bytes(fixed)).kind == inpath.UNPARSED_TCP
    bad_offset = bytearray(tcp(framed(ANSWER)))
    bad_offset[32] = 0x10  # a data offset of four bytes
    assert inpath.read_packet(bytes(bad_offset)).kind == inpath.UNPARSED_TCP
    bad_offset[32] = 0xF0  # one past the end of the packet
    assert inpath.read_packet(bytes(bad_offset[:60])).kind == inpath.UNPARSED_TCP


# ---- the reader is linear, and agrees with the store's decoder on every well-formed answer ------------


def random_answer(rng: random.Random) -> bytes:
    records = []
    for _ in range(rng.randrange(0, 12)):
        kind = rng.choice(("a", "a", "aaaa", "cname", "txt"))
        if kind == "a":
            records.append((1, bytes(rng.randrange(256) for _ in range(4))))
        elif kind == "aaaa":
            records.append((28, rng.randbytes(16)))
        elif kind == "cname":
            records.append((5, name(f"n{rng.randrange(99)}.example")))
        else:
            records.append((16, rng.randbytes(rng.randrange(0, 40))))
    return dns(records, qname=f"h{rng.randrange(999)}.cdn.example")


def test_the_linear_reader_returns_the_a_records_the_stores_decoder_returns():
    rng = random.Random(64)
    for _ in range(500):
        msg = random_answer(rng)
        want = [ip4(r.value) for r in dnsmsg.decode_answers(msg) if r.rtype == "A"]
        assert dnsmsg.a_rdata(msg) == want


def test_the_two_fillers_admit_the_same_public_addresses():
    """The passive feeder (dnsgate.addresses) and this one differ only where this one is stricter: the
    private, shared and link-local ranges."""
    rng = random.Random(18)
    for _ in range(300):
        msg = random_answer(rng)
        passive = [ip4(x) for x in dnsgate.addresses(msg)]
        mine = list(inpath.read_packet(udp(msg)).addrs)
        assert mine == [x for x in passive if inpath.admissible(x)]


def test_no_compression_pointer_is_followed():
    """A loop of pointers, which the store's decoder refuses after 64 hops, costs this reader nothing:
    the name ends where the pointer stands."""
    loop = struct.pack(">HHHHHH", 1, 0x8180, 0, 2, 0, 0)
    loop += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ip4("203.0.113.5")  # owner: a pointer to itself
    loop += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ip4("203.0.113.6")
    with pytest.raises(dnsmsg.DnsFormatError):
        dnsmsg.decode_answers(loop)
    assert dnsmsg.a_rdata(loop) == [ip4("203.0.113.5"), ip4("203.0.113.6")]


def test_the_readers_work_is_bounded_by_the_messages_length():
    """The costliest answer MAX_DNS allows: as many records as fit, each owner a pointer to a name of
    127 labels. Each byte is looked at once, so the count of steps cannot pass the length."""
    long_name = b"".join(b"\x01a" for _ in range(126)) + b"\x00"
    msg = bytearray(struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + long_name + struct.pack(">HH", 1, 1))
    n = 0
    while len(msg) + 16 <= inpath.MAX_DNS:
        msg += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, n % 250 + 1])
        n += 1
    msg[6:8] = struct.pack(">H", n)
    steps = 0
    real = dnsmsg.skip_name

    def counted(m, off):
        nonlocal steps
        end = real(m, off)
        steps += end - off
        return end

    dnsmsg.skip_name = counted
    try:
        found = dnsmsg.a_rdata(bytes(msg))
    finally:
        dnsmsg.skip_name = real
    assert len(found) == n > 200
    assert steps <= len(msg)


def test_skip_name_refuses_what_is_not_a_name():
    assert dnsmsg.skip_name(name("a.example"), 0) == 11
    assert dnsmsg.skip_name(b"\x01a\xc0\x00rest", 0) == 4
    for bad in (b"", b"\x05ab", b"\xc0", b"\x40abc\x00", b"\x80abc\x00", b"\x3f" + b"a" * 63):
        with pytest.raises(dnsmsg.DnsFormatError):
            dnsmsg.skip_name(bad, 0)
    with pytest.raises(dnsmsg.DnsFormatError):
        dnsmsg.skip_name(b"".join(b"\x3f" + b"a" * 63 for _ in range(4)) + b"\x00", 0)  # 257 octets


def test_no_bytes_make_the_packet_reader_raise():
    """Cut, flipped and random packets with a fixed seed: read_packet returns a Parsed for each."""
    rng = random.Random(64)
    seeds = [udp(ANSWER), FIXED, tcp(framed(ANSWER)), udp(random_answer(rng)), tcp(framed(ANSWER, ANSWER))]
    cases = [s[:n] for s in seeds for n in range(len(s) + 1)]
    for s in seeds:
        for _ in range(1500):
            b = bytearray(s)
            for _ in range(rng.randint(1, 4)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            cases.append(bytes(b))
    cases += [rng.randbytes(rng.randrange(0, 120)) for _ in range(3000)]
    cases += [b"\x45" + rng.randbytes(rng.randrange(19, 200)) for _ in range(3000)]
    kinds = set()
    for packet in cases:
        parsed = inpath.read_packet(packet)
        kinds.add(parsed.kind)
        assert all(len(x) == 4 and inpath.admissible(x) for x in parsed.addrs)
        assert parsed.kind == inpath.ANSWER or not parsed.addrs
    assert kinds == {inpath.ANSWER, inpath.TRUNCATED, inpath.UNPARSED_UDP, inpath.UNPARSED_TCP, inpath.OTHER}


# ---- what the filler remembers ------------------------------------------------------------------------


def test_an_address_is_known_for_a_minute_after_its_add():
    known = inpath.Known()
    known.add([b"aaaa"], 100.0)
    assert known.fresh(b"aaaa", 100.0) and known.fresh(b"aaaa", 100.0 + inpath.KNOWN_FOR - 0.01)
    assert not known.fresh(b"aaaa", 100.0 + inpath.KNOWN_FOR)
    assert not known.fresh(b"bbbb", 100.0)
    assert not known.fresh(b"aaaa", 99.0)  # a clock that stepped back makes nothing known


def test_the_memory_is_bounded_and_forgets_the_oldest_first():
    known = inpath.Known(keep=60, limit=3)
    for i, addr in enumerate((b"aaaa", b"bbbb", b"cccc", b"dddd")):
        known.add([addr], float(i))
    assert len(known) == 3 and not known.fresh(b"aaaa", 3.0) and known.fresh(b"bbbb", 3.0)
    known.add([b"bbbb"], 4.0)  # renewed: now the newest
    known.add([b"eeee"], 5.0)
    assert not known.fresh(b"cccc", 5.0) and known.fresh(b"bbbb", 5.0)
    known.add([b"ffff"], 200.0)  # everything older than a minute goes at the next add
    assert len(known) == 1
    known.clear()
    assert len(known) == 0


# ---- the decision ----------------------------------------------------------------------------------


class FakeAdder:
    """An adder that answers at once with `errno`, or never (`stuck`), and records what it was asked."""

    def __init__(self, result: int = 0, stuck: bool = False, full: bool = False):
        self.result, self.stuck, self.full = result, stuck, full
        self.jobs: list[inpath.Job] = []
        self.events: list = []

    def idle(self) -> bool:
        return all(j.done.is_set() for j in self.jobs)

    def submit(self, addrs):
        if self.full:
            return None
        job = inpath.Job(addrs)
        self.jobs.append(job)
        self.events.append(("add", addrs))
        if not self.stuck:
            job.errno = self.result
            job.done.set()
        return job

    def finish(self, result: int = 0) -> None:
        for job in self.jobs:
            if not job.done.is_set():
                job.errno = result
                job.done.set()


def filler(adder=None, hold_bound=0.01, clock=None):
    adder = adder or FakeAdder()
    released: list[int] = []
    logged: list[str] = []

    def release(packet_id):
        released.append(packet_id)
        adder.events.append(("release", packet_id))

    f = inpath.Filler(release, adder, clock or time.monotonic, logged.append, hold_bound)
    return f, adder, released, logged


def packet(packet_id: int, payload: bytes | None) -> nfnl.Packet:
    return nfnl.Packet(packet_id, 3, payload)


def test_an_answer_is_released_only_after_its_addresses_were_added():
    f, adder, _released, _ = filler()
    f.handle(packet(1, udp(ANSWER)), time.monotonic())
    assert adder.events == [("add", (ip4("203.0.113.5"), ip4("203.0.113.6"))), ("release", 1)]
    assert (f.stats.received, f.stats.held, f.stats.addresses) == (1, 1, 2)
    assert f.hold_micros()["n"] == 1


def test_the_release_waits_for_the_kernels_word_not_for_the_adds_start():
    """The add comes back 50 ms after it was handed over (another transaction held the lock): the
    packet is still unreleased at that moment, and released right after it."""
    adder = FakeAdder(stuck=True)
    f, _, released, _ = filler(adder, hold_bound=2.0)

    def finish():
        adder.events.append(("done", list(released)))
        adder.finish()

    timer = threading.Timer(0.05, finish)
    timer.start()
    t0 = time.monotonic()
    f.handle(packet(1, udp(ANSWER)), t0)
    timer.join()
    assert 0.04 <= time.monotonic() - t0 < 1.5
    assert [e[0] for e in adder.events] == ["add", "done", "release"]
    assert adder.events[1] == ("done", [])  # nothing had been released when the add came back
    assert released == [1] and (f.stats.held, f.stats.late) == (1, 0)
    assert 40_000 <= f.hold_micros()["p50"] < 1_500_000


def test_an_answer_whose_addresses_are_all_known_is_released_at_once():
    f, adder, _released, _ = filler()
    f.handle(packet(1, udp(ANSWER)), time.monotonic())
    adder.events.clear()
    f.handle(packet(2, udp(dns([a("203.0.113.6")]))), time.monotonic())
    assert adder.events == [("release", 2)] and f.stats.known == 1
    # one new address among known ones: the answer is held for that one alone
    f.handle(packet(3, udp(dns([a("203.0.113.6"), a("198.51.100.9")]))), time.monotonic())
    assert adder.events[1:] == [("add", (ip4("198.51.100.9"),)), ("release", 3)]


def test_a_known_address_is_added_again_once_its_minute_is_over():
    now = [1000.0]
    f, adder, _released, _ = filler(clock=lambda: now[0])
    f.handle(packet(1, udp(ANSWER)), now[0])
    now[0] += inpath.KNOWN_FOR + 1
    f.handle(packet(2, udp(ANSWER)), now[0])
    assert [e[0] for e in adder.events] == ["add", "release", "add", "release"]
    assert f.stats.held == 2 and f.stats.addresses == 4


@pytest.mark.parametrize(
    ("payload", "counter"),
    [
        (udp(dns([a("0.0.0.0")])), "empty"),
        (udp(dns([(28, bytes(16))])), "empty"),
        (udp(dns([], flags=0x8183)), "empty"),  # NXDOMAIN
        (udp(dns([a("203.0.113.5")], flags=0x8380)), "truncated"),
        (udp(ANSWER[:-1]), "unparsed_udp"),
        (tcp(framed(ANSWER)[:-1]), "unparsed_tcp"),
        (tcp(b""), "other"),
        (None, "other"),
    ],
)
def test_what_adds_nothing_is_released_at_once_and_counted(payload, counter):
    f, adder, _released, _ = filler()
    f.handle(packet(1, payload), time.monotonic())
    assert adder.events == [("release", 1)]
    assert getattr(f.stats, counter) == 1 and f.stats.held == 0 and f.stats.received == 1


def test_an_add_slower_than_the_bound_releases_the_answer_and_counts_it_late():
    f, _adder, released, logged = filler(FakeAdder(stuck=True), hold_bound=0.02)
    t0 = time.monotonic()
    f.handle(packet(1, udp(ANSWER)), t0)
    waited = time.monotonic() - t0
    assert released == [1] and 0.015 <= waited < 0.5
    assert (f.stats.late, f.stats.held) == (1, 0) and len(f.pending) == 1
    assert "an add took over 20 ms" in logged[0]


def test_the_bound_counts_from_the_packets_arrival_not_from_the_adds_start():
    f, _adder, released, _ = filler(FakeAdder(stuck=True), hold_bound=5.0)
    t0 = time.monotonic()
    f.handle(packet(1, udp(ANSWER)), t0 - 5.0)  # read from the socket five seconds late
    assert released == [1] and time.monotonic() - t0 < 1.0 and f.stats.late == 1


def test_while_an_add_is_out_later_answers_are_not_held_at_all():
    f, adder, _released, _ = filler(FakeAdder(stuck=True), hold_bound=0.01)
    f.handle(packet(1, udp(ANSWER)), time.monotonic())
    t0 = time.monotonic()
    f.handle(packet(2, udp(dns([a("198.51.100.1")]))), t0)
    f.handle(packet(3, udp(dns([a("198.51.100.2")]))), t0)
    assert time.monotonic() - t0 < 0.009  # neither waited for the bound
    assert adder.events[-4:] == [
        ("release", 2),
        ("add", (ip4("198.51.100.1"),)),
        ("release", 3),
        ("add", (ip4("198.51.100.2"),)),
    ]
    assert f.stats.late == 3 and len(f.pending) == 3
    # the adds come back: their addresses are known from then on, and answers are held again
    adder.finish()
    adder.stuck = False
    f.reap()
    assert f.pending == [] and f.stats.addresses == 4
    f.handle(packet(4, udp(dns([a("198.51.100.1")]))), time.monotonic())
    assert f.stats.known == 1
    f.handle(packet(5, udp(dns([a("198.51.100.3")]))), time.monotonic())
    assert f.stats.held == 1 and adder.events[-2:] == [("add", (ip4("198.51.100.3"),)), ("release", 5)]


def test_an_adder_that_is_too_far_behind_drops_the_add_and_never_the_answer():
    adder = FakeAdder(stuck=True)
    f, _, released, _ = filler(adder, hold_bound=0.005)
    f.handle(packet(1, udp(ANSWER)), time.monotonic())
    adder.full = True
    f.handle(packet(2, udp(dns([a("198.51.100.1")]))), time.monotonic())
    assert released == [1, 2] and f.stats.adds_dropped == 1 and f.stats.late == 2


def test_a_missing_set_releases_the_answer_and_forgets_what_was_known():
    f, adder, released, logged = filler()
    f.handle(packet(1, udp(ANSWER)), time.monotonic())
    adder.result = errno.ENOENT  # the table went away: an apply in progress, DNSGATE=off
    f.handle(packet(2, udp(dns([a("198.51.100.1")]))), time.monotonic())
    assert released == [1, 2] and (f.stats.failed, f.stats.adds_failed) == (1, 1)
    assert f.set_missing and len(f.known) == 0 and "is not there" in logged[-1]
    # the set is back: the address that was known is added again, not assumed
    adder.result = 0
    f.handle(packet(3, udp(ANSWER)), time.monotonic())
    assert f.stats.held == 2 and not f.set_missing


def test_an_add_the_kernel_refuses_is_counted_and_logged_once_a_minute():
    now = [50.0]
    f, _adder, released, logged = filler(FakeAdder(result=errno.EPERM), clock=lambda: now[0])
    for n in range(1, 4):
        f.handle(packet(n, udp(dns([a(f"198.51.100.{n}")]))), now[0])
    assert released == [1, 2, 3] and f.stats.failed == 3
    assert len(logged) == 1 and "EPERM" in logged[0]
    now[0] += inpath.LOG_EVERY
    f.handle(packet(4, udp(dns([a("198.51.100.4")]))), now[0])
    assert len(logged) == 2


def test_a_late_add_that_fails_is_counted_when_it_comes_back():
    f, adder, _released, _ = filler(FakeAdder(stuck=True), hold_bound=0.005)
    f.handle(packet(1, udp(ANSWER)), time.monotonic())
    adder.finish(errno.ENOENT)
    f.reap()
    assert f.stats.adds_failed == 1 and f.stats.late == 1 and f.stats.failed == 0 and f.set_missing


def test_whatever_breaks_inside_the_answer_is_still_released_exactly_once():
    class Broken(FakeAdder):
        def submit(self, addrs):
            raise RuntimeError("the adder fell over")

    f, _adder, released, logged = filler(Broken())
    f.handle(packet(1, udp(ANSWER)), time.monotonic())
    assert released == [1] and f.stats.errors == 1 and "internal error" in logged[0]

    class BrokenIdle(FakeAdder):
        def idle(self):
            raise OSError("no")

    f, _adder, released, _ = filler(BrokenIdle())
    f.handle(packet(2, udp(ANSWER)), time.monotonic())
    assert released == [2]


def test_a_gap_in_the_packet_ids_is_what_the_kernel_passed_itself():
    f, _adder, _released, _ = filler()
    for packet_id in (1, 2, 5, 6, 10):
        f.handle(packet(packet_id, udp(ANSWER)), time.monotonic())
    assert f.stats.kernel_passed == 5 and f.stats.received == 5
    f.handle(packet(3, udp(ANSWER)), time.monotonic())  # an id that goes back counts nothing
    assert f.stats.kernel_passed == 5


def test_every_packet_of_a_hostile_stream_is_released_exactly_once():
    """Random packets, a random adder (prompt, failing, stuck, full): one verdict each, and every packet
    is counted in exactly one outcome."""
    rng = random.Random(64)
    adder = FakeAdder()
    f, _, released, _ = filler(adder, hold_bound=0.0005)
    sent = []
    for packet_id in range(1, 1501):
        roll = rng.random()
        adder.stuck, adder.full = roll < 0.03, 0.03 <= roll < 0.05
        adder.result = errno.ENOENT if 0.05 <= roll < 0.08 else 0
        if rng.random() < 0.1:
            adder.finish(rng.choice((0, 0, errno.ENOENT)))
            adder.stuck = False
        base = rng.choice((udp(random_answer(rng)), tcp(framed(random_answer(rng))), rng.randbytes(60)))
        if rng.random() < 0.3:
            base = bytes(b if rng.random() > 0.05 else rng.randrange(256) for b in base)
        f.handle(packet(packet_id, base), time.monotonic())
        f.reap()
        sent.append(packet_id)
    assert released == sent
    st = f.stats
    outcomes = (
        st.held + st.known + st.empty + st.late + st.failed + st.truncated + st.unparsed_udp + st.unparsed_tcp
    )
    assert outcomes + st.other == st.received == 1500 and st.errors == 0
    assert st.held > 100 and st.late > 10 and st.failed > 5 and st.unparsed_udp + st.unparsed_tcp > 50


def test_the_real_adder_thread_bounds_a_blocked_add_and_recovers():
    """The Adder thread with an add that blocks in the kernel (a lock held by another transaction):
    the answer leaves at the bound, the loop's thread never waits longer, and the add is booked when
    it returns."""
    gate = threading.Event()
    calls = []

    def add(addrs):
        calls.append(addrs)
        gate.wait(5)
        return 0

    adder = inpath.Adder(add)
    adder.start()
    released = []
    f = inpath.Filler(released.append, adder, hold_bound=0.03, log=lambda line: None)
    t0 = time.monotonic()
    f.handle(packet(1, udp(ANSWER)), t0)
    assert released == [1] and 0.02 <= time.monotonic() - t0 < 1.0
    f.handle(packet(2, udp(dns([a("198.51.100.1")]))), time.monotonic())
    assert released == [1, 2] and f.stats.late == 2 and not adder.idle()
    gate.set()
    deadline = time.monotonic() + 5
    while f.pending and time.monotonic() < deadline:
        time.sleep(0.005)
        f.reap()
    assert f.pending == [] and f.stats.addresses == 3 and adder.idle()
    f.handle(packet(3, udp(dns([a("198.51.100.2")]))), time.monotonic())
    assert f.stats.held == 1 and len(calls) == 3


def test_the_adder_thread_survives_an_add_that_raises():
    results = iter([OSError(errno.ENOBUFS, "full"), ValueError("bug"), 0])

    def add(addrs):
        r = next(results)
        if isinstance(r, Exception):
            raise r
        return r

    adder = inpath.Adder(add)
    adder.start()
    got = []
    for _ in range(3):
        job = adder.submit((b"abcd",))
        assert job.done.wait(5)
        got.append(job.errno)
    assert got == [errno.ENOBUFS, errno.EIO, 0] and adder.is_alive()


def test_the_adders_backlog_is_bounded():
    gate = threading.Event()
    adder = inpath.Adder(lambda addrs: gate.wait(5) and 0, backlog=2)
    adder.start()
    jobs = [adder.submit((bytes([n] * 4),)) for n in range(6)]
    assert sum(j is None for j in jobs) >= 3  # one in hand, two waiting, the rest refused
    gate.set()


# ---- the loop --------------------------------------------------------------------------------------


def packet_bytes(packet_id: int, payload: bytes | None) -> bytes:
    attrs = nfnl.attr(nfnl.NFQA_PACKET_HDR, struct.pack(">IHB", packet_id, 0x0800, 3))
    if payload is not None:
        attrs += nfnl.attr(nfnl.NFQA_PAYLOAD, payload)
    return nfnl.message((nfnl.NFNL_SUBSYS_QUEUE << 8) | nfnl.NFQNL_MSG_PACKET, 0, 0, 2, inpath.QUEUE, attrs)


class FakeQueue:
    """The queue socket as the loop uses it: scripted datagrams in, verdicts out."""

    queue = inpath.QUEUE

    def __init__(self, datagrams=(), on_close=()):
        self.inbox = list(datagrams)
        self.early: list[bytes] = []
        self.on_close = list(on_close)
        self.released: list[int] = []
        self.events: list = []
        self.fail_release = 0

    def recv(self, wait, also=()):
        return self.inbox.pop(0) if self.inbox else None

    def release(self, packet_id):
        if self.fail_release:
            self.fail_release -= 1
            raise OSError(errno.ENOBUFS, "no buffer space")
        self.released.append(packet_id)
        self.events.append(("release", packet_id))

    def close_queue(self, wait=1.0):
        self.events.append("close_queue")
        self.early += self.on_close
        return 0


def loop(datagrams=(), live_result=0, adder=None, clock=None, **kw):
    adder = adder or FakeAdder()
    q = FakeQueue(datagrams, **kw)
    lives: list[bool] = []

    def live(on):
        lives.append(on)
        q.events.append(("live", on))
        return live_result() if callable(live_result) else live_result

    pings: list[int] = []
    docs: list[dict] = []
    f_holder = {}
    f = inpath.Filler(
        lambda i: f_holder["loop"].release(i), adder, clock or time.monotonic, lambda s: None, 0.01
    )
    lp = inpath.Loop(
        q, f, live, lambda: pings.append(1), docs.append, clock or time.monotonic, lambda: 1793020000.0
    )
    f_holder["loop"] = lp
    return lp, q, lives, pings, docs


def run_until_empty(lp, q, rounds=50):
    n = [0]

    def stop():
        n[0] += 1
        return not q.inbox or n[0] > rounds

    lp.run(stop)


def test_the_loop_decides_each_queued_packet_and_releases_it():
    lp, q, lives, pings, docs = loop(
        [packet_bytes(1, udp(ANSWER)), packet_bytes(2, udp(dns([a("0.0.0.0")])))]
    )
    run_until_empty(lp, q)
    assert q.released == [1, 2]
    assert (lp.filler.stats.held, lp.filler.stats.empty) == (1, 1)
    assert lives == [True] and lp.live and pings and docs


def test_two_packets_in_one_datagram_and_an_error_between_them():
    both = packet_bytes(7, udp(ANSWER)) + ack_bytes(0, errno.ENOENT) + packet_bytes(8, None)
    lp, q, *_ = loop([both])
    run_until_empty(lp, q)
    assert q.released == [7, 8] and lp.filler.stats.verdict_errors == 1


def test_a_datagram_that_does_not_parse_is_counted_and_the_loop_goes_on():
    bad = packet_bytes(1, udp(ANSWER))[:-3]
    no_id = nfnl.message(
        (nfnl.NFNL_SUBSYS_QUEUE << 8), 0, 0, 2, inpath.QUEUE, nfnl.attr(nfnl.NFQA_PAYLOAD, b"x")
    )
    lp, q, *_ = loop([bad, no_id, packet_bytes(2, udp(ANSWER))])
    run_until_empty(lp, q)
    assert q.released == [2] and lp.filler.stats.errors == 2


def test_a_verdict_that_cannot_be_sent_is_tried_again_then_counted():
    lp, q, *_ = loop([packet_bytes(1, udp(ANSWER))])
    q.fail_release = 1
    run_until_empty(lp, q)
    assert q.released == [1] and lp.filler.stats.verdict_errors == 0
    q.inbox.append(packet_bytes(2, udp(ANSWER)))
    q.fail_release = 2
    run_until_empty(lp, q)
    assert q.released == [1] and lp.filler.stats.verdict_errors == 1


def test_the_watchdog_is_fed_five_times_in_its_two_seconds_and_only_by_a_loop_that_turns():
    now = [0.0]
    lp, _q, lives, pings, docs = loop(clock=lambda: now[0])
    for tenth in range(200):  # 20 seconds of an idle loop, a tick every 0.1 s
        now[0] = tenth / 10
        lp.tick()
    assert 40 <= len(pings) <= 50  # every PING_EVERY = 0.4 s, or the tick after
    assert inpath.PING_EVERY * 4 <= 2.0  # the unit's WatchdogSec, with room for a late tick
    before = len(pings)
    now[0] += 30  # the loop stood still: nothing fed the watchdog meanwhile
    assert len(pings) == before
    assert len(lives) == 10 and len(docs) == 2  # the switch every 2 s, the status every 10 s


def test_the_live_switch_follows_the_table():
    result = [errno.ENOENT]
    now = [0.0]
    lp, _q, lives, _, docs = loop(live_result=lambda: result[0], clock=lambda: now[0])
    lp.filler.known.add([b"abcd"], 0.0)
    lp.tick()
    assert lp.live is False and len(lp.filler.known) == 0  # no table: nothing is held, nothing is known
    assert docs[-1]["live"] is False
    result[0] = 0
    now[0] += inpath.LIVE_EVERY - 1
    lp.tick()
    assert lp.live is False  # not asked again before its time
    now[0] += 1
    lp.tick()
    assert lp.live is True and lives == [True, True]
    # the port still there at the next look: nothing was lost, and what is known stays known
    lp.filler.known.add([b"abcd"], now[0])
    result[0] = errno.EEXIST
    now[0] += inpath.LIVE_EVERY
    lp.tick()
    assert lp.live is True and len(lp.filler.known) == 1
    # the port gone and put in anew: an apply made the table again, and resolved4_inpath with it
    result[0] = 0
    now[0] += inpath.LIVE_EVERY
    lp.tick()
    assert lp.live is True and len(lp.filler.known) == 0
    result[0] = errno.ENOENT  # DNSGATE=off applied under a running filler
    now[0] += inpath.LIVE_EVERY
    lp.tick()
    assert lp.live is False
    assert inpath.LIVE_EVERY <= 2  # how long answers pass unheld after an apply made the set anew


def test_the_status_holds_counts_and_times_and_no_address(tmp_path):
    lp, q, _, _, docs = loop([packet_bytes(1, udp(ANSWER)), packet_bytes(2, udp(ANSWER[:-1]))])
    run_until_empty(lp, q)
    lp._next["status"] = 0.0
    lp.tick()
    doc = docs[-1]
    assert doc["v"] == 1 and doc["queue"] == inpath.QUEUE and doc["live"] is True
    assert doc["stats"]["received"] == 2 and doc["stats"]["held"] == 1 and doc["stats"]["unparsed_udp"] == 1
    assert doc["hold_us"]["n"] == 1 and doc["hold_us"]["p50"] >= 0
    text = json.dumps(doc)
    assert "203.0.113" not in text and "cdn.example" not in text
    path = tmp_path / "status.json"
    assert inpath.write_status(str(path), doc) and json.loads(path.read_text(encoding="utf-8")) == doc
    assert not (tmp_path / "status.json.tmp").exists()
    assert oct(path.stat().st_mode & 0o777) == "0o640"  # its counts say how much the TV looked up
    assert doc["dropped_1h"] == 0
    assert inpath.write_status(str(tmp_path / "no" / "such" / "status.json"), doc) is False


def test_stopping_closes_the_switch_then_the_queue_then_releases_what_waited():
    waiting = [packet_bytes(8, udp(ANSWER)), ack_bytes(0, errno.ENOENT), packet_bytes(9, None)]
    lp, q, _lives, *_ = loop(on_close=waiting)
    lp.tick()
    q.early.append(packet_bytes(7, udp(ANSWER)))  # read early, not yet decided
    lp.drain()
    assert q.events == [
        ("live", True),
        ("live", False),
        "close_queue",
        ("release", 7),
        ("release", 8),
        ("release", 9),
    ]
    assert lp.filler.stats.drained == 3 and lp.live is False and q.early == []


class Deferred:
    """A `defer` that hands every transaction to nobody: each comes back only when the test says so."""

    def __init__(self):
        self.jobs: list[inpath.Job] = []

    def __call__(self, fn):
        job = inpath.Job(fn=fn)
        self.jobs.append(job)
        return job

    def finish(self, n: int = 0) -> None:
        job = self.jobs[n]
        job.errno = job.fn()
        job.done.set()


def test_the_switch_on_never_holds_the_loop_up():
    """A re-apply can hold nf_tables' lock for a while. The switch-on waits for it on the adder's
    thread; the loop goes on turning, asks only once, and says so in its status the moment it is back."""
    now = [0.0]
    lp, q, lives, pings, docs = loop(clock=lambda: now[0])
    deferred = Deferred()
    lp._defer = deferred
    lp.tick()
    assert lives == [] and lp.live is False and len(deferred.jobs) == 1  # asked, not answered
    for _ in range(5):
        now[0] += inpath.LIVE_EVERY
        lp.tick()
    assert len(deferred.jobs) == 1 and len(pings) >= 5  # not asked again while one is out; the loop turned
    written = len(docs)
    deferred.finish()
    now[0] += 0.1
    lp.tick()
    assert lives == [True] and lp.live is True
    assert len(docs) == written + 1 and docs[-1]["live"] is True  # at once, not at the next ten seconds
    q.inbox.append(packet_bytes(1, udp(ANSWER)))
    run_until_empty(lp, q)
    assert q.released == [1]


def test_a_stop_does_not_wait_for_a_switch_off_that_hangs():
    lp, q, _lives, *_ = loop(on_close=[packet_bytes(4, udp(ANSWER))])
    lp.tick()
    lp._defer = Deferred()
    t0 = time.monotonic()
    lp.drain(wait=0.05)
    assert 0.04 <= time.monotonic() - t0 < 1.0
    assert q.events[-2:] == ["close_queue", ("release", 4)] and lp.live is False


def test_the_adder_runs_any_transaction_in_its_turn():
    order = []
    adder = inpath.Adder(lambda addrs: order.append("add") or 0)
    adder.start()

    def refuse():
        raise OSError(errno.EPERM, "no")

    jobs = [adder.call(lambda: order.append("live") or 17), adder.submit((b"abcd",)), adder.call(refuse)]
    assert all(job.done.wait(5) for job in jobs)
    assert [job.errno for job in jobs] == [17, 0, errno.EPERM] and order == ["live", "add"]


def test_an_adder_busy_with_the_switch_does_not_make_an_answer_late():
    """Only an add that has not come back opens the breaker. The switch-on, every two seconds on the
    same thread, is over in a moment, and the answer waits for its own add behind it."""

    class Busy(FakeAdder):
        def idle(self):
            return False

    f, adder, released, _ = filler(Busy())
    f.handle(packet(1, udp(ANSWER)), time.monotonic())
    assert released == [1] and (f.stats.held, f.stats.late) == (1, 0)
    assert [e[0] for e in adder.events] == ["add", "release"]


def test_the_status_says_how_many_answers_the_kernel_dropped_in_the_last_hour():
    """A verdict the kernel refuses is an answer it had already dropped (a hook removed while it
    waited), the only trace such a drop leaves: the status carries the last hour's."""
    now = [0.0]
    wall = [1793020000.0]
    lp, _q, *_ = loop(clock=lambda: now[0])
    lp.wall = lambda: wall[0]
    lp.filler.stats.verdict_errors = 3
    lp.tick()
    assert lp.dropped_1h(wall[0]) == 3  # younger than an hour: everything since the start
    for step in range(1, 13):  # samples every ten minutes for two hours
        wall[0] += 600
        now[0] += 600
        if step == 8:
            lp.filler.stats.verdict_errors = 5
        lp.tick()
    assert lp.dropped_1h(wall[0]) == 2  # the three were more than an hour ago
    wall[0] += 3600
    now[0] += 3600
    lp.tick()
    assert lp.dropped_1h(wall[0]) == 0
    assert inpath.status(lp.filler, 1, True, 0.0, wall[0], 7)["dropped_1h"] == 7


def test_a_loop_whose_adder_died_ends_so_the_unit_restarts():
    lp, _q, *_ = loop([packet_bytes(1, udp(ANSWER))])
    lp.adder_alive = lambda: False
    with pytest.raises(RuntimeError):
        lp.run(lambda: False)


def test_hold_times_are_reported_in_microseconds():
    f, *_ = filler()
    assert f.hold_micros() == {"n": 0, "p50": 0, "p99": 0, "max": 0}
    f.holds = [0.0001 * n for n in range(1, 101)]
    assert f.hold_micros() == {"n": 100, "p50": 5100, "p99": 10000, "max": 10000}


# ---- the sockets, against a socket pair standing for the kernel ------------------------------------------


@pytest.fixture
def pair():
    ours, kernel = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    yield ours, kernel
    ours.close()
    kernel.close()


def test_a_transaction_reads_every_answer_already_there(pair):
    ours, kernel = pair
    nft = inpath.NftSocket(ours, wait=0.05)
    kernel.send(ack_bytes(2))
    kernel.send(ack_bytes(3))
    assert nft.add((ip4("203.0.113.5"),)) == 0
    assert kernel.recv(4096) == nfnl.setelem_add(
        1, "tvgw_gate", "resolved4_inpath", [ip4("203.0.113.5")], 86400
    )
    kernel.send(ack_bytes(5, errno.ENOENT))
    assert nft.live(True) == errno.ENOENT
    assert kernel.recv(4096) == nfnl.setelem_add(4, "tvgw_gate", "inpath_live", [b"\x00\x35"], create=True)
    kernel.send(ack_bytes(8, errno.EEXIST))  # the port was still there: the set was not made anew
    assert nft.live(True) == errno.EEXIST
    kernel.recv(4096)
    kernel.send(ack_bytes(11) + ack_bytes(12))
    assert nft.live(False) == 0
    assert kernel.recv(4096) == nfnl.set_flush(10, "tvgw_gate", "inpath_live")


def test_a_transaction_nobody_answers_is_a_failure_after_a_short_wait(pair):
    ours, kernel = pair
    nft = inpath.NftSocket(ours, wait=0.05)
    t0 = time.monotonic()
    assert nft.add((ip4("203.0.113.5"),)) == errno.EIO
    assert 0.04 <= time.monotonic() - t0 < 1.0
    kernel.close()
    assert nft.add((ip4("203.0.113.5"),)) != 0  # a dead socket is an errno, not an exception


def test_binding_keeps_whatever_arrives_before_the_acknowledgement(pair):
    ours, kernel = pair
    q = inpath.QueueSocket(sock=ours)
    early = packet_bytes(1, udp(ANSWER))
    kernel.send(early)
    kernel.send(ack_bytes(1))
    assert q.bind(wait=1.0) == 0
    assert kernel.recv(4096) == nfnl.queue_bind(inpath.QUEUE, 1, inpath.MAXLEN)
    assert q.recv(0.0) == early and q.recv(0.0) is None
    q.release(1)
    assert kernel.recv(4096) == nfnl.verdict(inpath.QUEUE, 1)


def test_a_bind_the_kernel_refuses_or_never_answers_is_an_errno(pair):
    ours, kernel = pair
    q = inpath.QueueSocket(sock=ours)
    kernel.send(ack_bytes(1, errno.EBUSY))
    assert q.bind(wait=1.0) == errno.EBUSY
    assert q.bind(wait=0.05) == errno.ETIMEDOUT


def test_closing_the_queue_leaves_every_packet_ahead_of_the_acknowledgement(pair):
    ours, kernel = pair
    q = inpath.QueueSocket(sock=ours)
    waiting = [packet_bytes(n, udp(ANSWER)) for n in (4, 5)]
    for data in waiting:
        kernel.send(data)
    kernel.send(ack_bytes(2))
    assert q.close_queue(wait=1.0) == 0 and q.early == waiting
    assert kernel.recv(4096) == nfnl.queue_maxlen(inpath.QUEUE, 2, 0)


def test_the_loops_wait_ends_when_a_signal_wakes_it(pair):
    ours, _kernel = pair
    q = inpath.QueueSocket(sock=ours)
    r, w = socket.socketpair()
    w.send(b"x")
    t0 = time.monotonic()
    assert q.recv(5.0, (r.fileno(),)) is None and time.monotonic() - t0 < 1.0
    r.close()
    w.close()


def test_notify_writes_one_datagram_to_the_socket_systemd_named(tmp_path):
    path = str(tmp_path / "notify")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as server:
        try:
            server.bind(path)
        except OSError:
            pytest.skip("the temporary path is too long for a unix socket")
        assert inpath.notify("WATCHDOG=1", {"NOTIFY_SOCKET": path}) is True
        assert server.recv(64) == b"WATCHDOG=1"
    assert inpath.notify("READY=1", {}) is False
    assert inpath.notify("READY=1", {"NOTIFY_SOCKET": "relative"}) is False
    assert inpath.notify("READY=1", {"NOTIFY_SOCKET": str(tmp_path / "nobody")}) is False


# ---- the kernel's own account of its queues ------------------------------------------------------------

PROC = """\
    0  12345     0 2 65531     0     0        9  1
53053   4242     3 2 65531     0     0   123456  1
garbage line
"""


def test_the_queue_table_is_read_by_column():
    queues = inpath.bound_queues(PROC)
    assert set(queues) == {0, 53053}
    assert queues[53053] == {
        "portid": 4242,
        "waiting": 3,
        "copy_mode": 2,
        "dropped": 0,
        "user_dropped": 0,
        "last_id": 123456,
    }
    assert inpath.bound_queues("") == {} and inpath.bound_queues("1 2 3\n") == {}


# ---- the settings ------------------------------------------------------------------------------------


def test_the_filler_runs_only_when_the_settings_ask_for_it(capsys):
    assert not inpath.wanted(config.Settings())  # the default is passive: nothing changes on an install
    assert inpath.wanted(config.Settings(dnsgate_fill="inpath"))
    assert not inpath.wanted(config.Settings(dnsgate="off", dnsgate_fill="inpath"))
    assert inpath.main(config.Settings()) == 0
    assert "DNSGATE_FILL=passive, nothing to hold" in capsys.readouterr().out


def test_the_setting_takes_two_values_and_defaults_to_passive(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_IP=10.10.10.17\n", encoding="utf-8")
    assert config.load(conf).dnsgate_fill == "passive"
    conf.write_text("DNSGATE_FILL=inpath\n", encoding="utf-8")
    assert config.load(conf).dnsgate_fill == "inpath"
    conf.write_text("DNSGATE_FILL=\n", encoding="utf-8")
    assert config.load(conf).dnsgate_fill == "passive"
    for bad in ("Inpath", "enforce", "yes"):
        conf.write_text(f"DNSGATE_FILL={bad}\n", encoding="utf-8")
        with pytest.raises(ValueError, match="DNSGATE_FILL"):
            config.load(conf)
