"""(mint) The minted-address shadow of design decision 96 without a kernel: what it reads out of an answer
the in-path filler has released and out of a copied opening, the class it puts each connection in (the
replay's, by what the table held then), when it cannot vouch, its socket, its memory's forget and its
status, and the two places the filler hands it work. The property under all of them: no bytes make it
raise, and it never sees an answer before the answer's verdict was given.

The kernel's half (the table's rule, its copies) is tests/virtual's; the apply's and verify's are below."""

import errno
import ipaddress
import json
import os
import re
import time

import pytest
import test_apply
from conftest import NOW, ROOT
from test_apply import CONF, nft_changes, run_apply
from test_apply import scripts as nft_scripts
from test_apply_check import checked
from test_apply_check import run_check as apply_check
from test_inpath import FakeAdder, a, dns, framed, ip4, tcp, udp
from test_nametap import FakeSock, log_message
from test_nfnl import ack_bytes

from tvgw import config, counting, db, inpath, mint, mintreplay, mintshadow, nfnl, verify
from tvgw.mintreplay import CROWDED, LAPSED, LISTED, LOCAL, NEVER, TICKET, TICKETS, UNASSESSED

TV = "10.10.10.17"
LIFE = mint.LIFETIME
ONE, TWO, NOBODY = "203.0.113.10", "203.0.113.20", "198.51.100.99"
FALLBACK = ("156.147.69.32", 8080)  # the LG profile's hardcoded update server
ON = {"dnsgate": "count", "dnsgate_fill": "inpath", "mint": "shadow"}


class Clock:
    def __init__(self, t: float):
        self.t = t

    def __call__(self) -> float:
        return self.t


def shadow(clock: Clock | None = None, assessed: bool = True, **kw) -> mintshadow.Shadow:
    """A shadow whose memory, when `assessed`, reaches back far enough to vouch at the clock's time."""
    clock = clock or Clock(NOW)
    sh = mintshadow.Shadow(clock, **kw)
    if assessed:
        sh.since = sh.last_miss = clock.t - LIFE - mintshadow.LOSS_PROTECT
    return sh


def opening(dst: str, dport: int | None = 443, proto: int = 6, sport: int = 40000, ihl: int = 5) -> bytes:
    """The first 64 bytes of a connection's first packet, as the rule copies them."""
    head = bytes([0x40 | ihl, 0, 0, 60, 0, 1, 0x40, 0, 64, proto, 0, 0]) + ip4(TV) + ip4(dst)
    head += b"\x01" * ((ihl - 5) * 4)
    ports = b"" if dport is None else sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
    return (head + ports + bytes(40))[:64]


def answered(sh: mintshadow.Shadow) -> None:
    """ONE answered for one name, TWO for two."""
    sh.answer(udp(dns([a(ONE)], qname="one.example")))
    sh.answer(udp(dns([a(TWO)], qname="left.example")))
    sh.answer(udp(dns([a(TWO)], qname="Right.Example")))


def judged(sh: mintshadow.Shadow) -> dict[str, int]:
    return {cls: n for cls, n in sh.counts.conns.items() if n}


# ---- what an answer and a copy give ----------------------------------------------------------------------
def test_the_filler_reads_the_name_beside_each_address_only_when_asked():
    plain = inpath.read_packet(udp(dns([a(ONE), a("0.0.0.0"), a(TWO)], qname="CDN.Example")))
    assert plain.addrs == (ip4(ONE), ip4(TWO)) and plain.named == ()  # the hold's reading, as before
    named = inpath.read_packet(udp(dns([a(ONE), a("0.0.0.0"), a(TWO)], qname="CDN.Example")), named=True)
    assert (
        named.named == (("cdn.example", ip4(ONE)), ("cdn.example", ip4(TWO))) and named.addrs == plain.addrs
    )
    two = framed(
        dns([a(ONE)], qname="a.example"),
        dns([a(ONE), a(TWO)], qname="b.example"),
        dns([a(ONE)], qname="a.example"),
    )
    assert inpath.read_packet(tcp(two), named=True).named == (
        ("a.example", ip4(ONE)),
        ("b.example", ip4(ONE)),
        ("b.example", ip4(TWO)),
    )
    assert inpath.read_packet(udp(dns([a(ONE)], qd=0)), named=True).named == ()  # no question, no name


@pytest.mark.parametrize(
    ("packet", "expected"),
    [
        pytest.param(opening(ONE, 443), (6, ip4(TV), ip4(ONE), 40000, 443), id="tcp"),
        pytest.param(opening(ONE, 3478, 17), (17, ip4(TV), ip4(ONE), 40000, 3478), id="udp"),
        pytest.param(opening(ONE, 443, ihl=7), (6, ip4(TV), ip4(ONE), 40000, 443), id="ip options"),
        pytest.param(opening(ONE, None, 1), (1, ip4(TV), ip4(ONE), None, None), id="icmp has no ports"),
        pytest.param(opening(ONE)[:23], None, id="cut inside the ports"),
        pytest.param(opening(ONE)[:19], None, id="cut inside the header"),
        pytest.param(opening(ONE, None, 1)[:19], None, id="an icmp copy cut inside the header"),
        pytest.param(b"\x60" + opening(ONE)[1:], None, id="not IPv4"),
        pytest.param(b"\x44" + opening(ONE)[1:], None, id="a header length under 20"),
        pytest.param(None, None, id="no payload"),
    ],
)
def test_an_opening_gives_its_protocol_addresses_and_ports(packet, expected):
    assert mintshadow.opening(packet) == expected


# ---- the classes ------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("dst", "dport", "after", "expected"),
    [
        pytest.param(ONE, 443, 30, TICKET, id="an address one name was answered with"),
        pytest.param(TWO, 443, 30, TICKETS, id="an address two names were answered with"),
        pytest.param(NOBODY, 443, 30, NEVER, id="an address no answer named"),
        pytest.param(*FALLBACK, 30, LISTED, id="the profile's hardcoded server"),
        pytest.param(FALLBACK[0], 443, 30, NEVER, id="that server on a port the profile does not list"),
        pytest.param(ONE, 443, LIFE - 1, TICKET, id="a second before the ticket's end"),
        pytest.param(ONE, 443, LIFE, LAPSED, id="at the ticket's end"),
        pytest.param(ONE, 443, mintshadow.NEWEST_FOR, NEVER, id="as long after as the memory keeps"),
        pytest.param("10.10.10.1", 443, 30, LOCAL, id="the gateway"),
        pytest.param("172.16.0.50", 8009, 30, LOCAL, id="a device at home"),
        pytest.param("8.8.8.8", 53, 30, LOCAL, id="DNS aimed at a public resolver"),
    ],
)
def test_each_connection_gets_the_replays_class(lg, dst, dport, after, expected):
    clock = Clock(NOW)
    sh = shadow(clock, listed=mintreplay.listed(lg))
    answered(sh)
    clock.t += after
    sh.copy(opening(dst, dport))
    assert judged(sh) == {expected: 1}
    assert sh.judge(dst, dport, clock.t) == expected  # the class, asked again, is the same


def test_an_answer_the_full_pool_could_not_mint_is_crowded_out_until_its_ticket_would_have_lapsed():
    clock = Clock(NOW)
    sh = shadow(clock, pool=ipaddress.ip_network("198.18.0.252/30"))  # three addresses given out
    for n in range(4):
        sh.answer(udp(dns([a(f"203.0.113.{n + 1}")], qname=f"n{n}.example")))
    assert sh.table.counts.refused == 1 and len(sh.table) == 3
    sh.copy(opening("203.0.113.4"))
    clock.t += LIFE
    sh.copy(opening("203.0.113.4", sport=40001))
    assert judged(sh) == {CROWDED: 1, LAPSED: 1}


def test_the_memory_stops_at_its_bounds_counts_a_miss_and_makes_room_as_tickets_end(monkeypatch):
    """The whole pool's table would take the filler's room; past MAX_TICKETS a new pair gets no ticket,
    and since the shadow cannot vouch for what it did not mint, that is a miss, not a crowded address.
    Past MAX_NEWEST the address answered longest ago is forgotten."""
    monkeypatch.setattr(mintshadow, "MAX_TICKETS", 2)
    monkeypatch.setattr(mintshadow, "MAX_NEWEST", 2)
    clock = Clock(NOW)
    sh = shadow(clock)
    answered(sh)  # three pairs: the third over the bound
    assert len(sh.table) == 2 and sh.counts.seen["full"] == 1 and sh.last_miss == NOW
    sh.answer(udp(dns([a(NOBODY)], qname="left.example")))  # a third address: ONE is forgotten
    assert list(sh.newest) == [ip4(TWO), ip4(NOBODY)] and sh.counts.seen["full"] == 2
    sh.answer(udp(dns([a(ONE)], qname="one.example")))  # a renewal needs no room
    assert sh.counts.seen["full"] == 2 and sh.table.counts.renewed == 1
    clock.t += LIFE  # every ticket has ended: room again
    sh.answer(udp(dns([a(TWO)], qname="right.example")))
    assert len(sh.table) == 1 and sh.counts.seen["full"] == 2
    sh.copy(opening(TWO))
    assert judged(sh) == {TICKET: 1}


def test_a_retried_opening_is_one_connection_until_two_minutes_have_passed(monkeypatch):
    monkeypatch.setattr(mintshadow, "MAX_SEEN", 2)
    clock = Clock(NOW)
    sh = shadow(clock)
    answered(sh)
    for _ in range(3):
        sh.copy(opening(ONE))
    clock.t += mintshadow.SEEN_FOR
    sh.copy(opening(ONE))
    assert judged(sh) == {TICKET: 1} and sh.counts.seen["again"] == 3
    clock.t += 0.001
    sh.copy(opening(ONE))
    sh.copy(opening(ONE, sport=40001))
    assert judged(sh) == {TICKET: 3}
    sh.copy(opening(ONE, sport=40002))  # a third remembered: the first is let go, and counts again
    sh.copy(opening(ONE))
    assert judged(sh) == {TICKET: 5}


@pytest.mark.parametrize(
    ("since", "last_miss", "expected"),
    [
        pytest.param(
            -LIFE, -mintshadow.LOSS_PROTECT - 1, NEVER, id="a memory of a lifetime, no miss in an hour"
        ),
        pytest.param(-LIFE + 1, -mintshadow.LOSS_PROTECT - 1, UNASSESSED, id="a memory a second short"),
        pytest.param(-LIFE, -mintshadow.LOSS_PROTECT, UNASSESSED, id="a miss an hour ago"),
    ],
)
def test_a_connection_without_a_ticket_is_judged_only_when_the_memory_can_vouch(since, last_miss, expected):
    sh = shadow(assessed=False)
    sh.since, sh.last_miss = NOW + since, NOW + last_miss
    sh.copy(opening(NOBODY))
    sh.copy(opening(ONE, sport=1))
    answered(sh)
    sh.copy(opening(ONE, sport=2))
    assert judged(sh) == {expected: 2, TICKET: 1}  # a ticket needs no vouching


def test_a_new_memory_cannot_vouch_for_an_hour_nor_reach_back_a_lifetime():
    clock = Clock(NOW)
    sh = shadow(clock, assessed=False)
    assert sh.since == sh.last_miss == NOW
    clock.t += LIFE + 1
    sh.copy(opening(NOBODY))
    assert judged(sh) == {NEVER: 1}


# ---- the answers -----------------------------------------------------------------------------------------
def test_each_answer_is_counted_by_what_it_was_and_one_not_read_is_a_miss():
    clock = Clock(NOW)
    sh = shadow(clock)
    sh.answer(udp(dns([a(ONE)], flags=0x8380)))  # the truncation bit: asked again over TCP
    sh.answer(tcp(framed(dns([a(ONE)], qname="one.example"))))
    sh.answer(udp(dns([], qname="empty.example")))
    sh.answer(udp(dns([a(ONE)])[:-1]))  # a message cut short
    sh.answer(udp(dns([a(ONE)])), whole=False)
    assert sh.counts.answers == {"read": 2, "truncated": 1, "unread": 2}
    assert sh.counts.seen["missed"] == 2 and sh.last_miss == NOW
    sh.copy(opening(ONE))
    sh.copy(opening(NOBODY))
    assert judged(sh) == {TICKET: 1, UNASSESSED: 1}


def test_a_miss_moves_the_refusals_since_it_to_unassessed_and_no_further_back():
    clock = Clock(NOW)
    sh = shadow(clock)
    for n, step in enumerate((0, 30, 31, 10)):
        clock.t += step
        sh.copy(opening(NOBODY, sport=n))
    assert judged(sh) == {NEVER: 4}
    sh.missed(NOW + 30)  # the switch was last seen in place at NOW + 30
    assert judged(sh) == {NEVER: 1, UNASSESSED: 3}
    sh.missed(NOW - 3600)  # however far back the switch was seen, a miss reaches back REJUDGE_FOR
    assert judged(sh) == {NEVER: 1, UNASSESSED: 3}
    assert clock.t - (NOW + 30) <= mintshadow.REJUDGE_FOR < clock.t - NOW


def test_no_bytes_make_the_shadow_raise_and_a_fault_costs_one_answer():
    import random

    rng = random.Random(96)
    sh = shadow()
    base = udp(dns([a(ONE)], qname="one.example"))
    for _ in range(400):
        junk = bytearray(base)
        for _ in range(rng.randrange(1, 6)):
            junk[rng.randrange(len(junk))] = rng.randrange(256)
        sh.answer(bytes(junk[: rng.randrange(len(junk) + 1)]))
        sh.copy(bytes(rng.randrange(256) for _ in range(rng.randrange(70))))
        sh.datagram(bytes(rng.randrange(256) for _ in range(rng.randrange(40))))
    assert sh.counts.errors >= 0 and len(sh.us) == 400

    class Broken(mint.Minter):
        def mint(self, *args):
            raise RuntimeError("a fault inside the table")

        def names_of(self, *args):
            raise RuntimeError("a fault inside the table")

    sh = shadow()
    sh.table = Broken()
    sh.answer(base)
    sh.copy(opening(ONE))
    assert sh.counts.errors == 2


# ---- the socket ------------------------------------------------------------------------------------------
def test_a_poll_reads_the_waiting_copies_and_no_more_than_its_bound():
    sh = shadow()
    answered(sh)
    sh.sock = FakeSock(
        [
            log_message(opening(ONE), 9) + log_message(opening(TWO), 9) + log_message(None, 9) + ack_bytes(1),
            OSError(errno.ENOBUFS, "no buffer space"),
            *[log_message(opening(NOBODY, sport=n), 9) for n in range(mintshadow.POLL_MAX)],
        ]
    )
    sh.poll()
    assert judged(sh) == {TICKET: 1, TICKETS: 1, NEVER: mintshadow.POLL_MAX - 2}
    assert sh.counts.seen["copies"] == mintshadow.POLL_MAX + 1  # the bare copy is one, the kernel's ack none
    assert sh.counts.seen["dropped"] == 1 and sh.counts.seen["missed"] == 0  # a copy carries no answer
    sh.poll()
    sh.poll()  # nothing waits: the read ends at once
    assert sh.counts.conns[NEVER] == mintshadow.POLL_MAX


def test_a_socket_that_fails_is_closed_and_waited_on_no_more():
    class Sock(FakeSock):
        closed = False

        def fileno(self):
            return 7

        def close(self):
            self.closed = True

    sock = Sock([OSError(errno.EBADF, "bad file descriptor"), log_message(opening(ONE), 9)])
    sh = shadow(sock=sock)
    assert sh.fds() == (7,)
    sh.poll()
    assert sock.closed and sh.sock is None and sh.fds() == () and sh.counts.errors == 1
    sh.poll()
    assert sh.counts.seen["copies"] == 0 and sh.status()["reading"] is False


# ---- the forget, the seed, the status ---------------------------------------------------------------------
def test_a_forget_empties_the_memory_at_the_next_status_and_an_older_stamp_does_not(tmp_path):
    stamp = tmp_path / "run" / "mint-forget"
    assert mintshadow.forget(str(stamp)) is False and not stamp.exists()  # no filler runs: no memory
    stamp.parent.mkdir()
    assert mintshadow.forget(str(stamp)) is True
    os.utime(stamp, (NOW - 10, NOW - 10))
    clock = Clock(NOW)
    sh = shadow(clock, forget_path=str(stamp))
    answered(sh)
    sh.tick()
    assert len(sh.table) == 3 and sh.counts.seen["forgotten"] == 0  # the stamp came before this memory
    clock.t += 5
    os.utime(stamp, (NOW + 5, NOW + 5))
    sh.tick()
    assert len(sh.table) == 0 and not sh.newest and sh.since == sh.last_miss == NOW + 5
    assert sh.counts.seen["forgotten"] == 1
    sh.tick()
    assert sh.counts.seen["forgotten"] == 1
    stamp.unlink()
    fresh = shadow(clock, forget_path=str(stamp))  # no stamp when this memory began
    answered(fresh)
    assert mintshadow.forget(str(stamp)) and fresh.tick() is None and len(fresh.table) == 0


def test_the_first_memory_comes_from_the_query_log(tmp_path):
    from conftest import DNS_ALLOWED

    from tvgw import adguard

    log = tmp_path / "querylog.json"
    log.write_text(DNS_ALLOWED, encoding="utf-8")
    at = adguard.parse_time(json.loads(DNS_ALLOWED)["T"])
    sh = shadow(Clock(at + 60), assessed=False)
    assert mintshadow.seed(sh, str(log), TV) == 1 and sh.since == at + 60 - LIFE
    assert sh.table.names_of(ip4("35.166.189.68"), at + 61) == ("us.lgtvsdp.com",)
    assert sh.last_miss == at + 60  # a start is a miss all the same: AdGuard writes in batches
    for path in (tmp_path / "missing.json", tmp_path):  # not there, and not a file it can read
        missing = shadow(Clock(at), assessed=False)
        assert mintshadow.seed(missing, str(path), TV) == 0 and missing.since == at


def test_a_first_memory_cut_short_reaches_back_to_its_oldest_answer_and_none_from_the_future(monkeypatch):
    from tvgw import adguard

    def record(t, qname="one.example", answers=f"A:{ONE}"):
        return adguard.DnsRecord(t, TV, qname, "A", answers, False, "", None, None, None, False, 1.0)

    rows = [record(NOW - 7200), record(NOW - 60, qname=""), record(NOW + 60, answers=f"A:{TWO}")]
    monkeypatch.setattr(adguard, "records_since", lambda *a, **kw: (rows, False))
    sh = shadow(Clock(NOW), assessed=False)
    assert mintshadow.seed(sh, __file__, TV) == 1 and sh.since == NOW - 7200
    assert list(sh.newest) == [ip4(ONE)]  # the nameless record and the one from the future left out


def test_the_status_holds_counts_and_times_and_no_name_or_address():
    clock = Clock(NOW)
    sh = shadow(clock, timer=iter(range(0, 1000, 3)).__next__)
    answered(sh)
    sh.copy(opening(ONE))
    doc = sh.status()
    assert set(doc) == {"since", "reading", "pool", "tickets", "conns", "answers", "seen", "errors", "us"}
    assert doc["tickets"]["live"] == doc["tickets"]["minted"] == 3 and doc["pool"] == 130_048
    assert doc["conns"][TICKET] == 1 and set(doc["conns"]) == {LOCAL, *mintreplay.JUDGED}
    assert doc["us"] == {"n": 3, "p50": 3_000_000, "p99": 3_000_000}
    text = json.dumps(doc)
    assert "203.0.113" not in text and "example" not in text
    assert {(part, key) for part, key, _rule in mintshadow.SERIES} <= {
        (part, key) for part in ("conns", "tickets", "answers", "seen") for key in doc[part]
    }
    assert all(rule.startswith(inpath.RULE_PREFIX) for _p, _k, rule in mintshadow.SERIES)
    assert mintshadow.COPY_RULE.startswith(inpath.RULE_PREFIX)  # kept out of "Firewall held" with them
    assert shadow().status()["us"] == {"n": 0, "p50": 0, "p99": 0}
    clock.t += LIFE
    assert sh.status()["tickets"]["live"] == 0  # the tickets that ended are not counted alive


# ---- where the filler hands it work ----------------------------------------------------------------------
class Spy:
    """A shadow that records what the filler hands it, in order with the filler's own events."""

    def __init__(self, events):
        self.events = events

    def answer(self, payload, whole=True):
        self.events.append(("shadow", payload))

    def missed(self, since=None):
        self.events.append(("missed", since))

    def fds(self):
        return (99,)

    def poll(self):
        self.events.append("poll")

    def tick(self):
        self.events.append("tick")

    def status(self):
        return {"since": 0.0}


def test_the_filler_hands_each_answer_over_after_its_verdict_whatever_happened():
    adder = FakeAdder()
    spy = Spy(adder.events)
    f = inpath.Filler(lambda i: adder.events.append(("release", i)), adder, time.monotonic, lambda s: None)
    f.shadow = spy
    pkt = udp(dns([a(ONE)]))
    f.handle(nfnl.Packet(1, 3, pkt), time.monotonic())
    f.handle(nfnl.Packet(4, 3, pkt), time.monotonic())  # ids 2 and 3 the kernel passed itself

    def boom(*_):
        raise RuntimeError("a fault in the reading")

    f._decide = boom
    f.handle(nfnl.Packet(5, 3, b"x"), time.monotonic())
    assert adder.events == [
        ("add", (ip4(ONE),)),
        ("release", 1),
        ("shadow", pkt),
        ("missed", None),
        ("release", 4),
        ("shadow", pkt),
        ("release", 5),
        ("shadow", b"x"),
    ]


def test_the_loop_waits_on_the_copies_reads_them_after_answers_and_says_the_switch_was_gone():
    from test_inpath import loop, packet_bytes, run_until_empty

    walls = iter(range(100, 200)).__next__
    result = [0]
    lp, q, _lives, _, docs = loop(
        [packet_bytes(1, udp(ANSWER := dns([a(ONE)])))], live_result=lambda: result[0]
    )
    events: list = []
    lp.filler.shadow = Spy(events)
    lp.wall = walls
    asked: list = []
    q.recv = lambda wait, also=(): asked.append(also) or (q.inbox.pop(0) if q.inbox else None)
    run_until_empty(lp, q)
    assert asked[0] == (99,) and events[:2] == [("missed", None), "tick"]
    assert ("shadow", udp(ANSWER)) in events and events.index("poll") > events.index(("shadow", udp(ANSWER)))
    assert docs[-1]["mint"] == {"since": 0.0}
    seen = lp._present_at
    result[0] = errno.EEXIST
    lp._next["live"] = 0.0
    lp.tick()
    assert lp._present_at > seen and ("missed", lp._present_at) not in events
    last = lp._present_at
    result[0] = 0  # an apply made the table anew: the port was gone since it was last seen
    lp._next["live"] = 0.0
    lp.tick()
    assert events[-1] == ("missed", last) or ("missed", last) in events


# ---- the setting, the unit's start -----------------------------------------------------------------------
@pytest.mark.parametrize(
    ("kw", "wanted"),
    [
        pytest.param(ON, True, id="shadow with the in-path filler"),
        pytest.param({**ON, "mint": "off"}, False, id="off"),
        pytest.param({**ON, "dnsgate_fill": "passive"}, False, id="no in-path filler"),
        pytest.param({**ON, "dnsgate": "off"}, False, id="no gate"),
    ],
)
def test_the_shadow_runs_only_where_the_filler_keeps_it(kw, wanted):
    assert mintshadow.wanted(config.Settings(**kw)) is wanted


def test_only_off_and_shadow_are_settings(tmp_path):
    conf = tmp_path / "tvgw.conf"
    for value in ("off", "shadow"):
        conf.write_text(f"MINT={value}\n", encoding="utf-8")
        assert config.load(conf).mint == value
    conf.write_text("MINT=on\n", encoding="utf-8")
    with pytest.raises(ValueError, match="MINT"):
        config.load(conf)
    assert config.Settings().mint == "off"


def test_the_start_binds_its_group_and_seeds_or_leaves_the_filler_alone(monkeypatch, tmp_path, capsys):
    from tvgw import nametap

    bound: list = []

    class Sock:
        def __init__(self, group):
            bound.append(group)

        def bind(self):
            return result

        def close(self):
            bound.append("closed")

    monkeypatch.setattr(nametap, "LogSocket", Sock)
    settings = config.Settings(**ON, adguard_querylog=str(tmp_path / "none.json"))
    assert mintshadow.start(config.Settings()) is None and bound == []
    result = errno.EBUSY
    assert mintshadow.start(settings) is None and bound == [9, "closed"]
    assert "could not bind NFLOG group 9 (another process holds it)" in capsys.readouterr().out
    result = 0
    sh = mintshadow.start(settings)
    assert isinstance(sh.sock, Sock) and "0 answers remembered" in capsys.readouterr().out


# ---- verify, the counting line, forget ---------------------------------------------------------------------
TABLE = f'\t\t... comment "{mintshadow.COPY_RULE}"'
PROC = "    9   4242     0 2  64    100  1\n"


def status_doc(t: float, **section) -> str:
    counts = {"conns": {NEVER: 3, TICKET: 4321}, "reading": True, "since": t - 7200, **section}
    return json.dumps({"t": t, "stats": {}, "mint": counts})


def mint_check(settings, table=TABLE, proc=PROC, doc=None):
    files = {verify.PROC_LOG: proc, inpath.STATUS: doc if doc is not None else status_doc(NOW - 5)}
    return verify.mint_check(settings, lambda argv: table, lambda p: files.get(p, ""), NOW)


def test_verify_says_not_in_use_when_off_and_warns_at_most_otherwise():
    check, series = mint_check(config.Settings())
    assert check.ok and not check.warn and "not in use (MINT=off)" in check.detail and series == []
    on = config.Settings(**ON)
    check, series = mint_check(on)
    assert check.ok and not check.warn and "counting, its memory from 2 hours ago" in check.detail
    assert (mintshadow.NEVER_RULE, 3, 0) in series and len(series) == len(mintshadow.SERIES)
    assert "3 " not in check.detail and "4321" not in check.detail  # no count where others may read it
    for settings, kw, says, stored in (
        (config.Settings(mint="shadow"), {}, "needs DNSGATE=count and DNSGATE_FILL=inpath", False),
        (on, {"table": ""}, "missing: the copying rule", False),
        (on, {"proc": "    8   4242     0 2  4096    100  1\n"}, "no process holds NFLOG group 9", False),
        (on, {"doc": status_doc(NOW - 120)}, "status file is 2 minutes old", False),
        (on, {"doc": json.dumps({"t": NOW - 5, "stats": {}})}, "or has no shadow", False),
        (on, {"doc": status_doc(NOW - 5, reading=False)}, "its copies' socket failed", True),
    ):
        check, series = mint_check(settings, **kw)
        assert check.ok and check.warn and says in check.detail and bool(series) is stored, says
    assert verify.FAIL_AFTER["mint_shadow"] == verify.WARN and "mint_shadow" in verify.PLAIN
    assert "MINT" in verify.APPLY_KEYS


def test_the_counting_line_follows_the_never_series_and_the_owner_judges(tmp_path):
    conn = db.connect(str(tmp_path / "tvgw.db"))
    since = NOW - 15 * 86400
    rules = {key: rule for _part, key, rule in mintshadow.SERIES}
    for t, n in ((since, 0), (NOW - 3600, 3)):
        for key in (NEVER, LAPSED, UNASSESSED):
            conn.execute(
                "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, ?, 0)", (t, rules[key], n)
            )
    for t in range(int(since), int(NOW), 6 * 3600):  # snapshots every six hours: one unbroken run
        conn.execute(
            "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, 0, 0)", (t, rules[NEVER])
        )
    conn.commit()
    obs = counting.Observation(config.Settings(**ON), {mintshadow.NEVER_RULE})
    assert counting.observe(conn, obs, NOW)["mint"]["since"] == since
    assert not counting.MECHANISMS[[m.key for m in counting.MECHANISMS].index("mint")].active(
        counting.Observation(config.Settings(), {mintshadow.NEVER_RULE})
    )
    (row,) = [r for r in counting.status(conn, NOW) if r.key == "mint"]
    assert row.state == counting.REACHED and row.judgement.clean is None
    assert row.judgement.found == (
        "6 connections a strict stage would refuse (3 never answered, 3 lapsed, 0 crowded out); 3 not assessed"
    )
    lines = counting.status_lines(counting.file_text(counting.status(conn, NOW, judge=False)), NOW)
    assert any(line.startswith("  connections a stage that hands the TV made-up addresses") for line in lines)


# ---- the deploy tree ---------------------------------------------------------------------------------------
APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
BLOCKS = re.compile(r"# ---- \(mint\) begin.*?# ---- \(mint\) end ----\n", re.S)
APPLIED_LINE = re.compile(r"^printf '%s=%s\\n' MINT .*\n", re.M)
DELETE = "delete table inet tvgw_mint"
INPATH = "DNSGATE_FILL=inpath\n"


def calls(tmp_path) -> list[str]:
    return (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()


def test_off_is_the_script_without_the_blocks_but_one_settings_line(tmp_path, monkeypatch):
    """MINT=off, said or not, and MINT=shadow without the in-path filler, on a gateway whose last apply
    did not load the table: every nft command and every script handed to nft is what the script with the
    (mint) blocks and the settings line cut out runs."""
    cut = APPLIED_LINE.sub("", BLOCKS.sub("", APPLY))
    assert len(BLOCKS.findall(APPLY)) == 2 and "MINT" not in cut and "tvgw_mint" not in cut
    for n, (conf, line) in enumerate(
        (
            (CONF, "MINT=off\n"),
            (CONF + "MINT=off\n" + INPATH, "MINT=off\n"),
            (CONF + "MINT=shadow\n", "MINT=shadow\n"),
        )
    ):
        now, before = tmp_path / f"now{n}", tmp_path / f"cut{n}"
        out = run_apply(now, conf=conf)
        assert out.returncode == 0
        assert ("MINT=shadow needs DNSGATE=count and DNSGATE_FILL=inpath" in out.stderr) is (n == 2)
        with monkeypatch.context() as m:
            m.setattr(test_apply, "APPLY", cut)
            assert run_apply(before, conf=conf).returncode == 0
        assert nft_scripts(now) == nft_scripts(before) and calls(now) == calls(before)
        used = (now / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
        old = (before / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
        assert used.replace(line, "") == old and used.count(line) == 1


def test_shadow_loads_a_table_that_only_copies_and_off_takes_it_away_once(tmp_path):
    out = run_apply(tmp_path, conf=CONF + "MINT=shadow\n" + INPATH)
    assert out.returncode == 0, out.stderr
    loaded = nft_scripts(tmp_path)
    at = next(i for i, s in enumerate(loaded) if "table inet tvgw_mint {" in s)
    assert "resolved4_inpath" in loaded[-1] and at < len(loaded) - 1  # before the in-path block, the last
    table = loaded[at]
    assert table.splitlines()[:2] == ["table inet tvgw_mint", DELETE]
    assert "type filter hook forward priority filter + 26; policy accept;" in table
    assert (
        'iifname "eth0" ip saddr 10.10.10.0/24 ct state new counter log group 9 snaplen 64 queue-threshold 1'
        f' comment "{mintshadow.COPY_RULE}"' in table
    )
    verdicts = table.replace("policy accept;", "").replace("queue-threshold", "")
    assert not re.search(
        r"\b(drop|reject|accept|queue|dnat|snat|masquerade|redirect|jump|goto)\b|mark set", verdicts
    )
    used = config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))
    assert used["MINT"] == "shadow" and DELETE not in calls(tmp_path)
    assert run_apply(tmp_path, conf=CONF + INPATH).returncode == 0  # the key taken out: off
    assert calls(tmp_path).count(DELETE) == 1
    assert run_apply(tmp_path, conf=CONF + INPATH).returncode == 0  # off again: nothing left to take away
    assert calls(tmp_path).count(DELETE) == 1


def test_a_bad_value_stops_before_anything_and_the_check_renders_the_table_only_for_shadow(tmp_path):
    bad = run_apply(tmp_path / "bad", conf=CONF + "MINT=on\n")
    assert bad.returncode == 1 and "MINT must be off or shadow" in bad.stderr
    assert nft_changes(tmp_path / "bad") == []
    on = apply_check(tmp_path / "on", conf=CONF + "MINT=shadow\n" + INPATH)
    assert on.returncode == 0, on.stderr
    assert any(s.startswith("table inet tvgw_mint\n") for s in checked(tmp_path / "on"))
    off = apply_check(tmp_path / "off", conf=CONF + INPATH)
    assert off.returncode == 0 and "tvgw_mint" not in off.stdout


def test_the_names_the_script_and_the_shadow_share():
    assert re.search(rf"^MINT_GROUP={mintshadow.GROUP} ", APPLY, re.M)
    assert re.search(rf"^MINT_SNAPLEN={mintshadow.COPY_RANGE}$", APPLY, re.M)
    assert mintshadow.FORGET.startswith("/run/tvgw-dnsgate-inpath/") and inpath.STATUS.startswith(
        "/run/tvgw-dnsgate-inpath/"
    )
