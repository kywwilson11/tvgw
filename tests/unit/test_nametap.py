"""(namebound) The live name count, stage 2 of design decision 70, without a kernel: the NFLOG messages, what it
reads out of a copied answer and a copied hello, the memory and its bounds, each class counted once per
connection, the losses it cannot see past, its first memory from the query log, the loop, the brief's line
and verify's check. The property under all of them: no bytes make it raise, and nothing it does can hold or
change a packet, since it only ever reads copies.

The kernel's half (the table's rules, the copies, their order on one socket) is tests/virtual's."""

import dataclasses
import errno
import io
import json
import random
import re
import shutil
import struct
import subprocess
import sys

import pytest
import test_apply
from conftest import NOW, ROOT, UNITS
from corpus import build
from test_apply import CONF, STUBS, run_apply
from test_apply import scripts as nft_scripts
from test_apply_check import checked
from test_apply_check import run_check as apply_check
from test_inpath import a, dns, framed, ip4, name
from test_nfnl import ack_bytes

from tvgw import cli, config, db, nametap, nfnl, queries, verify
from tvgw.namebound import WINDOW

little_endian = pytest.mark.skipif(sys.byteorder != "little", reason="the fixtures are little-endian")
TV, GW = "10.10.10.17", "10.10.10.1"


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


def cname(target: str) -> tuple[int, bytes]:
    return 5, name(target)


def ipv4(src: str, dst: str, proto: int, payload: bytes, frag: int = 0x4000) -> bytes:
    return (
        struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, frag, 64, proto, 0, ip4(src), ip4(dst))
        + payload
    )


def answer_udp(msg: bytes) -> bytes:
    return ipv4(GW, TV, 17, struct.pack(">HHHH", 53, 40000, 8 + len(msg), 0) + msg)


def answer_tcp(data: bytes) -> bytes:
    return ipv4(GW, TV, 6, struct.pack(">HHIIBBHHH", 53, 40001, 1, 1, 5 << 4, 0x18, 1000, 0, 0) + data)


def segment(dst: str, data: bytes, sport: int = 50000, seq: int = 1000, flags: int = 0x18) -> bytes:
    return ipv4(TV, dst, 6, struct.pack(">HHIIBBHHH", sport, 443, seq, 1, 5 << 4, flags, 1000, 0, 0) + data)


def spec(sni: str, late: bool = False):
    """A Chromium-style hello without the GREASE ECH extension: the CX's engine predates ECH, and a hello
    carrying the extension for a name never answered counts as ECH, as the store's check counts it."""
    s = build.chrome_pq("t", sni, late_sni=late)
    return dataclasses.replace(s, extensions=[e for e in s.extensions if e[0] != 0xFE0D])


def hello(sni: str, late: bool = False) -> bytes:
    return spec(sni, late).record()


class Clock:
    def __init__(self, t: float = NOW):
        self.t = t

    def __call__(self) -> float:
        return self.t


def tap(assessed_from: float = NOW - WINDOW, clock: Clock | None = None, **kw) -> nametap.Tap:
    return nametap.Tap(GW, clock or Clock(), assessed_from, **kw)


def reasons(t: nametap.Tap) -> dict[str, int]:
    found = {k: getattr(t.stats, k) for k in nametap.UNASSESSED_REASONS if getattr(t.stats, k)}
    assert sum(found.values()) == t.stats.unassessed  # every connection not assessed has its one reason
    return found


def counts(t: nametap.Tap) -> dict[str, int]:
    st = t.stats
    return {
        k: getattr(st, k)
        for k in ("bound", "shared", "never", "noname", "ech", "unassessed")
        if getattr(st, k)
    }


# ---- netlink ---------------------------------------------------------------------------------------------
BIND = h("28000000 0104 0500 01000000 00000000 00 00 0008 0500 0100 01 000000 0a00 0200 00001000 02 00 0000")


@little_endian
def test_the_bind_is_one_message_naming_the_group_and_whole_packets():
    assert nfnl.log_bind(8, 1, 4096) == BIND
    unbind = nfnl.log_unbind(8, 2)
    assert struct.unpack_from("=IHHI", unbind)[1:4] == ((4 << 8) | 1, 0x0005, 2) and unbind[16:20] == h(
        "00000008"
    )
    assert unbind[20:28] == h("0500 0100 02 000000")


def log_message(packet: bytes | None, group: int = 8) -> bytes:
    attrs = nfnl.attr(nfnl.NFULA_PACKET_HDR, struct.pack(">HBB", 0x0800, 3, 0))
    if packet is not None:
        attrs += nfnl.attr(nfnl.NFULA_PAYLOAD, packet)
    return nfnl.message((nfnl.NFNL_SUBSYS_ULOG << 8) | nfnl.NFULNL_MSG_PACKET, 0, 0, 2, group, attrs)


def test_a_copy_is_read_out_of_its_message_and_nothing_else_is():
    pkt = answer_udp(dns([a("203.0.113.5")]))
    (msg,) = nfnl.messages(log_message(pkt))
    assert nfnl.log_packet(msg) == pkt
    (bare,) = nfnl.messages(log_message(None))
    assert nfnl.log_packet(bare) is None
    (other,) = nfnl.messages(ack_bytes(1))
    assert nfnl.log_packet(other) is None
    with pytest.raises(nfnl.NlError):
        nfnl.log_packet(nfnl.Msg((nfnl.NFNL_SUBSYS_ULOG << 8) | nfnl.NFULNL_MSG_PACKET, 0, 0, b"\x02"))


# ---- reading a copy --------------------------------------------------------------------------------------
def test_an_answer_binds_its_question_and_its_chain_to_its_public_addresses():
    msg = dns(
        [cname("edge.cdn.example"), a("203.0.113.5"), a("10.10.10.1"), a("0.0.0.0"), a("203.0.113.5")],
        qname="App.Example",
    )
    assert nametap.read_answer(answer_udp(msg)) == [(["app.example", "edge.cdn.example"], ["203.0.113.5"])]
    two = framed(dns([a("203.0.113.6")], qname="a.example"), dns([a("203.0.113.7")], qname="b.example"))
    assert nametap.read_answer(answer_tcp(two)) == [
        (["a.example"], ["203.0.113.6"]),
        (["b.example"], ["203.0.113.7"]),
    ]
    assert nametap.read_answer(answer_udp(dns([a("203.0.113.5")], flags=0x0100))) == [([], [])]  # a question
    assert nametap.read_answer(answer_udp(dns([a("203.0.113.5")], flags=0x8380))) == [([], [])]  # truncated
    assert nametap.read_answer(answer_udp(dns(an=3))) is None  # counts that do not fit
    assert nametap.read_answer(answer_udp(b"\x00" * 5000)) is None  # longer than the reader reads
    assert nametap.read_answer(answer_tcp(framed(dns([a("203.0.113.6")]))[:-3])) is None  # cut mid-message
    assert nametap.read_answer(ipv4(GW, TV, 17, b"\x00\x35", frag=0x2000)) is None  # a fragment


def test_no_bytes_make_the_tap_raise():
    rng = random.Random(70)
    t = tap()
    seeds = [
        answer_udp(dns([cname("x.example"), a("203.0.113.5")])),
        segment("203.0.113.5", hello("x.example")),
    ]
    for _ in range(3000):
        base = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 8)):
            base[rng.randrange(len(base))] = rng.randrange(256)
        t.copy(bytes(base[: rng.randint(0, len(base))]))
        t.copy(bytes(rng.randrange(256) for _ in range(rng.randint(0, 64))))
    t.copy(None)
    assert t.stats.copies == 6001 and t.stats.errors == 0


# ---- the memory ------------------------------------------------------------------------------------------
def test_the_memory_binds_for_a_day_and_lets_the_oldest_go_first():
    m = nametap.Memory(max_addresses=2, max_names=2)
    m.remember(["a.example"], ["203.0.113.1"], NOW)
    assert m.judge("a.example", "203.0.113.1", NOW + WINDOW) == "bound"
    assert m.judge("a.example", "203.0.113.1", NOW + WINDOW + 1) == "never"
    assert m.judge("b.example", "203.0.113.1", NOW + 5) == "shared"
    m.remember(["b.example", "c.example"], ["203.0.113.1"], NOW + 1)  # three names: the soonest to go goes
    assert set(m.by_addr["203.0.113.1"]) == {"b.example", "c.example"} and "203.0.113.1" in m.crowded
    m.remember(["d.example"], ["203.0.113.2"], NOW)
    m.remember(["e.example"], ["203.0.113.3"], NOW)  # a third address: the oldest answered goes
    assert list(m.by_addr) == ["203.0.113.2", "203.0.113.3"] and not m.crowded


# ---- the count -------------------------------------------------------------------------------------------
def test_each_connection_is_counted_once_in_its_class():
    clock = Clock()
    t = tap(clock=clock)
    t.copy(answer_udp(dns([cname("app.cdn.example"), a("203.0.113.10")], qname="app.example")))
    clock.t += 0.01
    t.copy(segment("203.0.113.10", hello("app.example"), sport=50001))
    t.copy(segment("203.0.113.10", hello("app.example"), sport=50001))  # retransmitted: once
    t.copy(segment("203.0.113.10", b"", sport=50001, flags=0x10))  # a bare ACK: nothing
    t.copy(segment("203.0.113.10", hello("app.cdn.example"), sport=50002))  # a CNAME target
    t.copy(segment("203.0.113.10", hello("tracker.example"), sport=50003))  # another name on the address
    t.copy(segment("198.51.100.20", hello("app.example"), sport=50004))  # an address never answered
    t.copy(segment("198.51.100.21", build.no_sni().record(), sport=50005))
    t.copy(segment("198.51.100.22", build.ech_cloudflare().record(), sport=50006))
    t.copy(segment("198.51.100.23", b"GET / HTTP/1.1\r\n\r\n", sport=50007))  # not TLS
    t.copy(segment(GW, hello("gw.example"), sport=50008))  # the gateway: not counted
    t.copy(segment("192.168.1.4", hello("nas.example"), sport=50009))  # a LAN address: not counted
    assert counts(t) == {"bound": 2, "shared": 1, "never": 1, "noname": 1, "ech": 1}
    assert (t.stats.answers, t.stats.not_tls, t.stats.errors) == (1, 1, 0)
    doc = t.status(NOW - 60)
    assert [(s["name"], s["dst"], s["cls"]) for s in doc["samples"]] == [
        ("tracker.example", "203.0.113.10", "shared"),
        ("app.example", "198.51.100.20", "never"),
    ]
    assert doc["addresses"] == 1 and doc["stats"]["bound"] == 2 and json.dumps(doc)


def test_a_blocked_answer_binds_nothing():
    t = tap()
    t.copy(answer_udp(dns([a("0.0.0.0")], qname="tracker.example")))
    t.copy(segment("198.51.100.40", hello("tracker.example")))  # reached by an address of its own
    assert counts(t) == {"never": 1} and t.stats.answers == 1 and not t.memory.by_addr
    assert not t.memory.answered("tracker.example", NOW)


def test_a_hello_split_over_segments_is_read_when_its_name_arrives():
    t = tap()
    t.copy(answer_udp(dns([a("203.0.113.10")], qname="late.example")))
    record = hello("late.example", late=True)
    spans = {typ: (start, end) for typ, start, end in spec("late.example", late=True).ext_spans()}
    cut = spans[0][0] - 1  # just before the server name
    t.copy(segment("203.0.113.10", record[:cut], seq=1000))
    assert counts(t) == {} and len(t.pending) == 1
    t.copy(segment("203.0.113.10", record[:cut], seq=1000))  # the first again: still waiting
    ((_next, held, segments),) = t.pending.values()
    assert (counts(t), len(held), segments) == ({}, cut, 1)  # a retransmission is not read twice
    t.copy(segment("203.0.113.10", record[cut:], seq=1000 + cut))
    assert counts(t) == {"bound": 1} and not t.pending


def test_a_connection_the_memory_cannot_vouch_for_is_not_assessed_by_its_reason():
    clock = Clock()
    young = tap(assessed_from=NOW - 60, clock=clock)  # the memory holds a minute of answers
    young.copy(segment("198.51.100.30", hello("cached.example")))
    young.copy(answer_udp(dns([a("198.51.100.31")], qname="fresh.example")))
    young.copy(segment("198.51.100.31", hello("fresh.example"), sport=50001))  # bound needs no history
    assert counts(young) == {"unassessed": 1, "bound": 1} and reasons(young) == {"unassessed_start": 1}
    lossy = tap(clock=clock)
    lossy.lost()
    clock.t += 30
    lossy.copy(segment("198.51.100.32", hello("x.example")))
    clock.t += nametap.LOSS_PROTECT
    lossy.copy(segment("198.51.100.33", hello("y.example"), sport=50001))
    assert counts(lossy) == {"unassessed": 1, "never": 1} and lossy.stats.lost == 1
    assert reasons(lossy) == {"unassessed_loss": 1}
    crowded = tap(clock=clock)
    crowded.memory = nametap.Memory(max_names=1)
    crowded.copy(answer_udp(dns([a("198.51.100.34")], qname="a.example")))
    crowded.copy(answer_udp(dns([a("198.51.100.34")], qname="b.example")))
    crowded.copy(segment("198.51.100.34", hello("a.example")))  # let go to make room: cannot say
    assert counts(crowded) == {"unassessed": 1} and reasons(crowded) == {"unassessed_crowded": 1}


def test_names_whose_day_is_over_go_first_and_crowd_no_address():
    """The review's case: an address answered for 64 names over 64 days, then one more. Every earlier name's
    day is over, so none is let go early, the address is not crowded, and a mismatch there is `shared`."""
    clock = Clock()
    t = tap(clock=clock)
    for day in range(64):
        clock.t = NOW + day * WINDOW
        t.copy(answer_udp(dns([a("203.0.113.70")], qname=f"n{day}.example")))
    clock.t = NOW + 64 * WINDOW
    t.copy(answer_udp(dns([a("203.0.113.70")], qname="n64.example")))
    # only the day before is still in its day (a day binds through its last second)
    assert not t.memory.is_crowded("203.0.113.70", clock.t) and len(t.memory.by_addr["203.0.113.70"]) == 2
    clock.t += 1
    t.copy(segment("203.0.113.70", hello("tracker.example")))
    assert counts(t) == {"shared": 1}
    # sixty-five names inside one day: the soonest to expire goes, and the address is crowded for its day
    m = nametap.Memory(max_names=64)
    for i in range(65):
        m.remember([f"m{i}.example"], ["203.0.113.71"], NOW + i)
    assert m.is_crowded("203.0.113.71", NOW + 100) and not m.is_crowded("203.0.113.71", NOW + WINDOW + 1)


def test_an_answer_that_cannot_be_read_protects_the_hour_after_it():
    clock = Clock()
    t = tap(clock=clock)
    t.copy(answer_tcp(framed(dns([a("203.0.113.80")], qname="split.example"))[:-3]))  # across segments
    assert t.stats.answers_unread == 1 and t.stats.unparsed == 0
    clock.t += 600
    t.copy(segment("203.0.113.80", hello("split.example")))  # its answer was the one not read
    clock.t += nametap.LOSS_PROTECT
    t.copy(segment("203.0.113.81", hello("other.example"), sport=50001))
    assert counts(t) == {"unassessed": 1, "never": 1} and reasons(t) == {"unassessed_loss": 1}


def test_the_minutes_after_start_vouch_only_for_addresses_a_live_answer_showed():
    """AdGuard Home writes its query log in batches, so the newest lookups are missing from the memory
    read at start: until STARTUP_GRACE has passed, a mismatch at an address no live copy showed is not
    assessed; one at an address a live answer showed, or after the grace, is counted."""
    clock = Clock()
    t = tap(clock=clock, started=NOW)
    t.copy(segment("203.0.113.90", hello("unwritten.example")))
    t.copy(answer_udp(dns([a("203.0.113.91")], qname="live.example")))
    t.copy(segment("203.0.113.91", hello("other.example"), sport=50001))
    clock.t += nametap.STARTUP_GRACE
    t.copy(segment("203.0.113.92", hello("later.example"), sport=50002))
    assert counts(t) == {"unassessed": 1, "shared": 1, "never": 1} and reasons(t) == {"unassessed_start": 1}
    assert not t.live_seen  # let go once the grace is over


def test_the_samples_names_are_tagged_as_the_store_tags_them():
    t = tap(tag=lambda name, at: "t-1-0123456789.example" if name.endswith("show.example") else name)
    t.copy(segment("203.0.113.95", hello("a.show.example")))
    t.copy(segment("203.0.113.96", hello("plain.example"), sport=50001))
    assert [x["name"] for x in t.samples] == ["t-1-0123456789.example", "plain.example"]

    def unreadable(name, at):
        raise PermissionError("the name keys are root's")

    t = tap(tag=unreadable)
    t.copy(segment("203.0.113.95", hello("a.show.example")))
    assert t.samples[0]["name"] is None and t.stats.never == 1


def test_the_first_memory_comes_from_the_query_log(tmp_path):
    from conftest import DNS_ALLOWED

    log = tmp_path / "querylog.json"
    log.write_text(DNS_ALLOWED, encoding="utf-8")
    t = tap(assessed_from=NOW)
    record_t = json.loads(DNS_ALLOWED)["T"]
    from tvgw import adguard

    at = adguard.parse_time(record_t)
    n, since = nametap.seed(t, str(log), TV, at + 60)
    assert n == 1 and since == at + 60 - WINDOW  # the read reached past the window: all of it known
    assert t.memory.judge("us.lgtvsdp.com", "35.166.189.68", at + 120) == "bound"
    assert t.memory.judge("us-lgtvsdp-com.aws-prd.net", "35.166.189.68", at + 120) == "bound"
    assert nametap.seed(tap(), str(tmp_path / "missing.json"), TV, NOW) == (0, NOW)  # no log, no proof


# ---- the loop --------------------------------------------------------------------------------------------
class FakeSock:
    def __init__(self, items):
        self.items = list(items)

    def recv(self, wait, also=()):
        if not self.items:
            return None
        item = self.items.pop(0)
        if isinstance(item, OSError):
            raise item
        return item


def test_the_loop_reads_every_copy_counts_losses_and_publishes():
    published = []
    pkt_answer = answer_udp(dns([a("203.0.113.10")], qname="app.example"))
    pkt_hello = segment("203.0.113.10", hello("app.example"))
    sock = FakeSock(
        [
            log_message(pkt_answer) + log_message(pkt_hello),  # one datagram, two copies, in order
            OSError(errno.ENOBUFS, "full"),
            ack_bytes(1),  # an acknowledgement: no copy
            b"\x01\x00",  # bytes that are no message
        ]
    )
    t = tap()
    ticks = iter(range(100))
    nametap.run(
        sock, t, lambda: not sock.items, published.append, NOW - 10, clock=lambda: next(ticks) * 0.001
    )
    assert counts(t) == {"bound": 1} and t.stats.lost == 1 and t.stats.copies == 2
    assert published and published[-1]["stats"]["lost"] == 1
    with pytest.raises(OSError):
        nametap.run(FakeSock([OSError(errno.EBADF, "bad")]), tap(), lambda: False, published.append, NOW)


def test_the_bind_reads_the_kernels_answer():
    class Sock:
        def __init__(self, reply):
            self.reply, self.sent = reply, []

        def send(self, data):
            self.sent.append(data)

        def recv(self, n):
            return self.reply

        def fileno(self):
            return 0

    import select

    ok = nametap.LogSocket(sock=Sock(ack_bytes(1)))
    real = select.select
    try:
        select.select = lambda r, w, x, t: (r, [], [])
        assert ok.bind() == 0 and ok.sock.sent[0][:4] == nfnl.log_bind(8, 1, 4096)[:4]
        busy = nametap.LogSocket(sock=Sock(ack_bytes(1, errno.EBUSY)))
        assert busy.bind() == errno.EBUSY
    finally:
        select.select = real


def test_the_command_does_nothing_unless_the_settings_ask(tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_IP=10.10.10.17\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "names-tap"]) == 0
    assert "NAME_BINDING=off, nothing to count" in capsys.readouterr().out
    assert config.Settings().name_binding == "off" and config.CHOICES["NAME_BINDING"] == ("off", "count")


# ---- the store and the brief ------------------------------------------------------------------------------
def test_the_names_the_store_the_script_and_the_tap_share():
    from conftest import ROOT

    apply = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
    assert queries.NAMES_RULE == nametap.RULE_PREFIX
    comments = set(re.findall(r'comment "(names: [^"]+)"', apply))
    assert comments == set(nametap.COPY_RULES)
    assert all(rule.startswith(nametap.RULE_PREFIX) and rule not in comments for _k, rule in nametap.SERIES)
    assert {k for k, _r in nametap.SERIES} <= set(nametap.Stats.__dataclass_fields__)
    assert not any(c.startswith(p) for c in comments for p, _ in queries.FW_LINES)
    (group,) = re.findall(r"^NAMES_GROUP=(\d+)", apply, re.M)
    assert int(group) == nametap.GROUP and "log group $NAMES_GROUP snaplen $NAMES_SNAPLEN" in apply
    assert "NAMES_SNAPLEN=4096" in apply and nametap.COPY_RANGE == 4096 == nametap.MAX_DNS


def test_the_brief_shows_the_live_count_and_keeps_it_out_of_firewall_held(tmp_path, lg):
    conn = db.connect(str(tmp_path / "n.db"))
    rows = []
    for t, k in ((NOW - 7200, 0), (NOW - 600, 1)):
        rows += [(t, rule, 10 * k + i, 0) for i, (_key, rule) in enumerate(nametap.SERIES)]
        rows += [(t, rule, 100 * k, 0) for rule in nametap.COPY_RULES]
    conn.executemany("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)", rows)
    conn.commit()
    a, b = NOW - 3600, NOW
    live = nametap.window(conn, a, b)
    assert live["bound"] == 10 and live["shared"] == 10 and live["copied"] == 300
    assert nametap.window(conn, NOW - 99999, NOW - 90000) is None
    o = queries.window_report(conn, a, b, lg, now=NOW)
    assert o["names"]["live"] == live
    assert not [x for x in o["firewall"]["activity"] if x["rule"].startswith("names:")]
    buf = io.StringIO()
    cli.render_brief(o, buf)
    assert "live count (stage 2, from the firewall's copies as they happened):" in buf.getvalue()


# ---- verify ----------------------------------------------------------------------------------------------
TABLE = "\n".join(f'\t\t... comment "{c}"' for c in nametap.COPY_RULES)
PROC = "    8   4242     0 2  4096    100  1\n"


def status(t: float, **stats) -> str:
    return json.dumps({"t": t, "started": t - 3600, "stats": {"bound": 5, "lost": 0, **stats}})


def names_check(settings, table=TABLE, proc=PROC, doc=None):
    files = {verify.PROC_LOG: proc, nametap.STATUS: doc if doc is not None else status(NOW - 5)}
    return verify.names_check(settings, lambda argv: table, lambda p: files.get(p, ""), NOW)


def test_verify_says_not_in_use_when_off_and_stores_nothing():
    check, series = names_check(config.Settings())
    assert check.ok and not check.warn and "not in use (NAME_BINDING=off)" in check.detail and series == []


def test_verify_reads_the_table_the_group_and_the_status_and_stores_the_counts():
    on = config.Settings(name_binding="count")
    check, series = names_check(on)
    assert check.ok and not check.warn and "bound and counting" in check.detail
    assert ("names: TLS connections name-bound", 5, 0) in series and len(series) == len(nametap.SERIES)
    assert "5" not in check.detail.split(";")[0]  # no count where others may read it
    for kw, says in (
        ({"table": ""}, "missing: the UDP answers' rule"),
        ({"proc": "    7   4242     0 2  4096    100  1\n"}, "no process holds NFLOG group 8"),
        ({"doc": status(NOW - 120)}, "status file is 2 minutes old"),
        ({"doc": "not json"}, "status file is missing"),
    ):
        check, series = names_check(on, **kw)
        assert check.ok and check.warn and says in check.detail and series == [], kw
    assert verify.FAIL_AFTER["names_tap"] == verify.WARN and "names_tap" in verify.PLAIN
    assert verify.log_groups("garbage\n 12 1 0 2 1 1 1\n") == {12}


# ---- the deploy tree: tvgw-apply, the unit, the installer ------------------------------------------------
APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
INSTALL = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
UNIT = (UNITS / "tvgw-names.service").read_text(encoding="utf-8")
BLOCKS = re.compile(r"# ---- \(namebound\) begin.*?# ---- \(namebound\) end ----\n", re.S)
APPLIED_LINE = re.compile(r"^printf '%s=%s\\n' NAME_BINDING .*\n", re.M)
DELETE = "delete table inet tvgw_names"
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")


def calls(tmp_path) -> list[str]:
    return (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()


@needs_bash
def test_off_is_the_script_without_the_blocks_but_one_settings_line(tmp_path, monkeypatch):
    """NAME_BINDING=off, said or not, on a gateway whose last apply did not load the count: every nft
    command, and every script handed to nft, is what the script with the (namebound) blocks and the
    settings line cut out runs. The only difference is NAME_BINDING=off in settings.applied."""
    cut = APPLIED_LINE.sub("", BLOCKS.sub("", APPLY))
    assert len(BLOCKS.findall(APPLY)) == 2 and "NAME_BINDING" not in cut and "tvgw_names" not in cut
    for n, conf in enumerate(
        (CONF, CONF + "NAME_BINDING=off\n", CONF + "DNSGATE_FILL=inpath\nCAPTURE_MODE=headers\n")
    ):
        now, before = tmp_path / f"now{n}", tmp_path / f"cut{n}"
        assert run_apply(now, conf=conf).returncode == 0
        with monkeypatch.context() as m:
            m.setattr(test_apply, "APPLY", cut)
            assert run_apply(before, conf=conf).returncode == 0
        assert nft_scripts(now) == nft_scripts(before)
        assert calls(now) == calls(before)
        used = (now / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
        old = (before / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
        assert used.replace("NAME_BINDING=off\n", "") == old and used.count("NAME_BINDING=off\n") == 1


@needs_bash
def test_off_after_count_takes_the_table_away_once(tmp_path):
    assert run_apply(tmp_path, conf=CONF + "NAME_BINDING=count\n").returncode == 0
    assert DELETE not in calls(tmp_path)  # the load deletes and makes it inside its own script
    assert run_apply(tmp_path, conf=CONF).returncode == 0  # the key taken out: off
    assert calls(tmp_path).count(DELETE) == 1
    assert run_apply(tmp_path, conf=CONF).returncode == 0  # off again: nothing left to take away
    assert calls(tmp_path).count(DELETE) == 1


@needs_bash
def test_count_loads_the_table_after_the_capture_and_before_the_in_path_block(tmp_path):
    conf = CONF + "NAME_BINDING=count\nDNSGATE_FILL=inpath\nCAPTURE_MODE=headers\n"
    out = run_apply(tmp_path, conf=conf)
    assert out.returncode == 0, out.stderr
    loaded = nft_scripts(tmp_path)
    names = next(i for i, s in enumerate(loaded) if "table inet tvgw_names {" in s)
    assert "tvgw_capture" in loaded[names - 1] and "resolved4_inpath" in loaded[names + 1] == loaded[-1]
    table = loaded[names]
    assert table.splitlines()[:2] == ["table inet tvgw_names", DELETE]
    assert table.count("log group 8 snaplen 4096 queue-threshold 1") == 3
    assert "type filter hook output priority filter + 6; policy accept;" in table
    assert "type filter hook forward priority filter + 25; policy accept;" in table
    assert 'iifname "eth0" ip saddr 10.10.10.0/24 ip saddr != 10.10.10.1 tcp dport 443' in table
    verdicts = table.replace("policy accept;", "").replace("queue-threshold", "")
    assert not re.search(
        r"\b(drop|reject|accept|queue|dnat|snat|masquerade|redirect|jump|goto)\b|mark set", verdicts
    )
    used = config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))
    used.pop("WAN_GW_USED")
    assert used["NAME_BINDING"] == "count" and used == verify.apply_settings(conf)
    assert DELETE not in calls(tmp_path)  # the load's own delete is inside the script, never a command


@needs_bash
def test_a_refused_table_only_warns_and_a_bad_value_stops_before_anything(tmp_path):
    keep = 'cat >"$STUB_DIR/nft-script.$n" ;;'
    refuses = STUBS["nft"].replace(
        keep, 'cat >"$STUB_DIR/nft-script.$n"; ! grep -q tvgw_names "$STUB_DIR/nft-script.$n" || exit 1 ;;'
    )
    out = run_apply(tmp_path / "refused", conf=CONF + "NAME_BINDING=count\n", stubs={"nft": refuses})
    assert out.returncode == 0, out.stderr
    assert "tvgw: names table not loaded; the live name count reads nothing" in out.stderr
    forwarding = tmp_path / "refused" / "proc" / "sys" / "net" / "ipv4" / "conf" / "eth0" / "forwarding"
    assert forwarding.read_text(encoding="utf-8") == "1\n"  # the TV is online all the same
    bad = run_apply(tmp_path / "bad", conf=CONF + "NAME_BINDING=enforce\n")
    assert bad.returncode == 1 and "NAME_BINDING must be off or count" in bad.stderr
    assert not (tmp_path / "bad" / "stub" / "nft.calls").exists()


@needs_bash
def test_the_check_renders_the_table_only_for_count(tmp_path):
    on = apply_check(tmp_path / "on", conf=CONF + "NAME_BINDING=count\n")
    assert on.returncode == 0, on.stderr
    rendered = checked(tmp_path / "on")
    assert rendered[-1].startswith("table inet tvgw_names\n") and on.stdout == "".join(rendered)
    off = apply_check(tmp_path / "off")
    assert off.returncode == 0 and "tvgw_names" not in off.stdout and "names:" not in off.stdout
    assert on.stdout.startswith(off.stdout)


def unit_value(key: str) -> str:
    (value,) = re.findall(rf"^{key}=(.*)$", UNIT, re.M)
    return value


def test_the_unit_holds_nothing_back_and_is_sandboxed_like_the_filler():
    assert (unit_value("Type"), unit_value("NotifyAccess")) == ("notify", "main")
    assert "WatchdogSec" not in UNIT  # nothing waits for it, so nothing needs killing in a hurry
    assert (
        unit_value("ExecStart") == "/usr/local/bin/tvgw names-tap" and unit_value("Restart") == "on-failure"
    )
    assert f"/run/{unit_value('RuntimeDirectory')}/status.json" == nametap.STATUS
    filler = (UNITS / "tvgw-dnsgate-inpath.service").read_text(encoding="utf-8").splitlines()
    mine = UNIT.splitlines()
    for line in filler:
        if line.startswith(
            (
                "NoNewPrivileges",
                "Protect",
                "PrivateTmp",
                "SystemCallArch",
                "RestrictRealtime",
                "MemoryMax",
                "CapabilityBoundingSet",
                "AmbientCapabilities",
                "RestrictAddressFamilies",
                "RuntimeDirectoryMode",
            )
        ):
            assert line in mine, line
    assert not [line for line in mine if line.startswith(("Requires=", "BindsTo=", "Requisite="))]


@pytest.mark.parametrize(
    ("conf", "status"),
    [
        (None, 1),
        ("", 1),
        ("NAME_BINDING=off\n", 1),
        ("NAME_BINDING=count\n", 0),
        ("NAME_BINDING=count # live\n", 0),
        ("NAME_BINDING=\n", 1),
        ("NAME_BINDING=Count\n", 255),
        ("NAME_BINDING=enforce\n", 255),
    ],
)
def test_the_units_condition_runs_it_only_when_the_settings_ask(tmp_path, conf, status):
    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("needs sh")
    line = unit_value("ExecCondition")
    script = line[len("/bin/sh -c '") : -1].replace("$$", "$")
    path = tmp_path / "tvgw.conf"
    if conf is not None:
        path.write_text(conf, encoding="utf-8")
    out = subprocess.run(
        [sh, "-c", script.replace("/etc/tvgw/tvgw.conf", str(path))], capture_output=True, text=True
    )
    assert out.returncode == status, out.stderr


def installer_block(tmp_path, settings: str, enable_fails: bool = False) -> tuple[int, list[str], str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("install.sh is a bash script")
    (block,) = re.findall(r"# \(namebound\) The live name count runs only.*?\nfi\n", INSTALL, re.S)
    fake = tmp_path / "systemctl"
    fails = "enable" if enable_fails else "never"
    fake.write_text(f'#!/bin/sh\necho "$*" >>{tmp_path}/calls\n[ "$1" != {fails} ]\n', encoding="utf-8")
    fake.chmod(0o755)
    (tmp_path / "calls").write_text("", encoding="utf-8")
    script = (
        f"set -euo pipefail\nPATH={tmp_path}:$PATH\n{settings}\n"
        f'restart_changed() {{ echo "restart_changed $*" >>{tmp_path}/calls; }}\n{block}echo done\n'
    )
    out = subprocess.run([bash, "-c", script], capture_output=True, text=True, encoding="utf-8")
    return (
        out.returncode,
        (tmp_path / "calls").read_text(encoding="utf-8").splitlines(),
        out.stdout + out.stderr,
    )


@pytest.mark.parametrize("settings", ["", "NAME_BINDING=off", "NAME_BINDING="])
def test_the_installer_leaves_the_unit_disabled_unless_the_settings_ask(tmp_path, settings):
    rc, got, out = installer_block(tmp_path, settings)
    assert rc == 0 and got == ["disable --now tvgw-names.service"] and out.strip() == "done"


def test_the_installer_enables_the_unit_for_count_never_fails_on_it_and_the_package_removes_it(tmp_path):
    (tmp_path / "ok").mkdir()
    rc, got, _ = installer_block(tmp_path / "ok", "NAME_BINDING=count")
    assert rc == 0 and got == ["enable --now tvgw-names.service", "restart_changed tvgw-names"]
    (tmp_path / "bad").mkdir()
    rc, got, out = installer_block(tmp_path / "bad", "NAME_BINDING=count", enable_fails=True)
    assert (
        rc == 0 and got == ["enable --now tvgw-names.service"] and "WARNING: tvgw-names did not start" in out
    )
    assert INSTALL.count("tvgw-names.service") == 2
    case = next(ln for ln in INSTALL.splitlines() if ln.strip().startswith("tvgw-dnsgate |"))
    assert "tvgw-names" in case.split(")")[0].split(" | ")
    prerm = (ROOT / "packaging" / "scripts" / "prerm").read_text(encoding="utf-8")
    assert "systemctl disable --now tvgw-names.service >/dev/null 2>&1 || true" in prerm
    example = (ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8")
    assert re.search(r"^NAME_BINDING=off$", example, re.M)
