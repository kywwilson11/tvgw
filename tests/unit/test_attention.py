"""(attention) Attention-keyed silence, its first stage (design decision 69): the TV's state from its own words,
the word the live reading writes, the holder that keeps the kernel's dead-man entries, the essentials the
fillers add, the samples, the report, the brief's section, the plain line and the check.

The holder is run against a model of the kernel's sets that decodes the very netlink bytes it sends, so
what is tested is what the kernel would be asked: a transaction is applied whole or not at all, and an
element is gone once its lifetime has passed. The property this stage rests on is tested from several
sides: whatever the live reading or the holder does, the TV's address is never in two states' sets, and
a word that stops, or a holder that stops, leaves it in none within FRESH or HOLD seconds."""

from __future__ import annotations

import errno
import json
import random
import sqlite3
import struct

import pytest
from test_forget import tree  # noqa: F401 - the forget tests' gateway, a fixture

from tvgw import appfront, attention, cli, config, db, dnsmsg, ingest, inpath, nfnl, plain, verify
from tvgw.config import Settings

TV = bytes([10, 10, 10, 17])
ON = Settings(live_reading="on")
T0 = 1_793_000_000.0  # 2026-10-25 local, any time will do


# ---- the state from the TV's own words -----------------------------------------------------------------
@pytest.mark.parametrize(
    ("power", "app", "state"),
    [
        (("Screen Saver", ""), "youtube.leanback.v4", attention.IDLE),
        (("Screen Saver", ""), "com.webos.app.hdmi1", attention.IDLE),  # the screen saver wins over the input
        (("Screen Saver", ""), None, attention.IDLE),  # and needs no app
        (("Active", ""), "com.webos.app.hdmi2", attention.INPUT),
        (("Active", ""), "com.webos.app.externalinput.av1", attention.INPUT),
        (("Active", ""), "com.webos.app.livetv", attention.LIVETV),
        (("Active", ""), "netflix", attention.APP),
        (("Active", ""), "", attention.APP),  # the home screen
        (("Active", ""), "invalid", attention.APP),  # an id the TV chose that cannot be kept
        (("Screen Off", ""), "spotify-beehive", attention.APP),  # the panel dark, the sound playing
        (("Active", ""), None, None),  # on, and no app said yet: unknown
        (None, "netflix", None),
        (("Active Standby", ""), "netflix", None),
        (("Active", "Request Power Off"), "netflix", None),  # switching off
        (("Warming Up", ""), "netflix", None),  # a word the vocabulary does not know
    ],
)
def test_the_state_comes_from_the_power_word_first_and_the_app_second(power, app, state):
    assert attention.state_of(power, app) == state


def test_where_it_runs_is_the_live_readings_profile_with_the_switch_not_off():
    assert attention.not_in_use(Settings()) == "LIVE_READING=off"
    assert attention.not_in_use(ON) is None and attention.wanted(ON)
    assert attention.not_in_use(Settings(live_reading="on", profile="samsung-tizen")) == (
        "PROFILE=samsung-tizen has no live reading"
    )
    assert attention.not_in_use(Settings(live_reading="on", attention_wall="off")) == "ATTENTION_WALL=off"
    assert attention.wanted(Settings(live_reading="on", attention_wall="refuse"))  # counts, as count


def test_the_setting_takes_exactly_its_three_values_count_first(tmp_path):
    assert config.Settings().attention_wall == "count" and config.CHOICES["ATTENTION_WALL"][0] == "count"
    conf = tmp_path / "tvgw.conf"
    for value in ("count", "off", "refuse"):
        conf.write_text(f"ATTENTION_WALL={value}\n")
        assert config.load(conf).attention_wall == value
    for near in ("Count", "on", "enforce", "yes"):
        conf.write_text(f"ATTENTION_WALL={near}\n")
        with pytest.raises(ValueError, match="ATTENTION_WALL"):
            config.load(conf)


# ---- the word -----------------------------------------------------------------------------------------
def test_a_word_reads_back_as_written_and_carries_the_state_alone():
    data = attention.encode_word(attention.INPUT, 1234.5678)
    assert attention.decode_word(data) == (attention.INPUT, 1234.568)
    assert set(json.loads(data)) == {"v", "state", "mono"}  # no app, no wall-clock time
    assert attention.decode_word(attention.encode_word(None, 9.0)) == (None, 9.0)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not json",
        b'{"v": 2, "state": "idle", "mono": 1}',
        b'{"v": 1, "state": "netflix", "mono": 1}',  # an app is never a state
        b'{"v": 1, "state": "idle", "mono": NaN}',
        b'{"v": 1, "state": "idle", "mono": true}',
        b'{"v": 1, "state": "idle"}',
        b'["idle", 1]',
        b'{"v": 1, "state": "idle", "mono": 1, "pad": "' + b"x" * 300 + b'"}',
        '{"v": 1, "state": "idlé", "mono": 1}'.encode(),
    ],
)
def test_anything_that_is_not_exactly_a_word_is_no_word(data):
    assert attention.decode_word(data) is None


def test_the_live_reading_writes_its_word_at_each_change_and_each_second_and_none_at_the_end(tmp_path):
    now = [100.0]
    path = tmp_path / "attention"
    word = attention.Word(str(path), clock=lambda: now[0])
    word.say(attention.APP)
    assert attention.read_word(str(path)) == (attention.APP, 100.0)
    now[0] += 0.4
    word.say(attention.APP)  # unchanged, and soon: not written again
    assert attention.read_word(str(path)) == (attention.APP, 100.0)
    word.say(attention.IDLE)  # a change: at once
    assert attention.read_word(str(path)) == (attention.IDLE, 100.4)
    now[0] += attention.WRITE_EVERY
    word.say(attention.IDLE)
    assert attention.read_word(str(path)) == (attention.IDLE, 101.4)
    word.clear()
    assert attention.read_word(str(path)) == (None, 101.4)
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_a_word_that_cannot_be_written_is_never_the_sessions_problem(tmp_path):
    word = attention.Word(str(tmp_path / "no-such-dir" / "attention"))
    word.say(attention.IDLE)  # no runtime directory: nothing raised
    word.clear()
    assert attention.read_word(str(tmp_path / "no-such-dir" / "attention")) is None


# ---- a model of the kernel's sets ---------------------------------------------------------------------
def _attrs(data: bytes) -> list[tuple[int, bytes]]:
    out, off = [], 0
    while len(data) - off >= 4:
        length, kind = struct.unpack_from("=HH", data, off)
        out.append((kind & nfnl.NLA_TYPE_MASK, data[off + 4 : off + length]))
        off += (length + 3) & ~3
    return out


class Kernel:
    """The inet tvgw_attn table's sets as nf_tables keeps them: elements with an expiry by the kernel's own
    clock, transactions applied whole or refused whole (ENOENT for a table or set that is not there)."""

    def __init__(self, clock):
        self.clock = clock
        self.sets: dict[str, dict[bytes, float]] | None = None
        self.load()
        self.transactions: list[list[tuple]] = []
        self.refuse: int | None = None

    def load(self) -> None:
        self.sets = {name: {} for name in attention.STATE_SETS.values()}

    def transact(self, build, parts: int = 1) -> int:
        msgs = list(nfnl.messages(build(7)))
        assert msgs[0].kind == nfnl.NFNL_MSG_BATCH_BEGIN and msgs[-1].kind == nfnl.NFNL_MSG_BATCH_END
        assert len(msgs) == parts + 2 and [m.seq for m in msgs] == list(range(7, 7 + parts + 2))
        ops = []
        for m in msgs[1:-1]:
            assert m.kind >> 8 == nfnl.NFNL_SUBSYS_NFTABLES
            found = dict(_attrs(m.body[4:]))
            table = found[nfnl.NFTA_SET_ELEM_LIST_TABLE].rstrip(b"\0").decode()
            name = found[nfnl.NFTA_SET_ELEM_LIST_SET].rstrip(b"\0").decode()
            if self.sets is None or table != attention.TABLE or name not in self.sets:
                return errno.ENOENT
            if m.kind & 0xFF == nfnl.NFT_MSG_DELSETELEM:
                assert nfnl.NFTA_SET_ELEM_LIST_ELEMENTS not in found  # a flush, never one element
                ops.append(("flush", name))
                continue
            assert m.kind & 0xFF == nfnl.NFT_MSG_NEWSETELEM
            for kind, elem in _attrs(found[nfnl.NFTA_SET_ELEM_LIST_ELEMENTS]):
                assert kind == nfnl.NFTA_LIST_ELEM
                e = dict(_attrs(elem))
                key = dict(_attrs(e[nfnl.NFTA_SET_ELEM_KEY]))[nfnl.NFTA_DATA_VALUE]
                (ms,) = struct.unpack(">Q", e[nfnl.NFTA_SET_ELEM_EXPIRATION])
                assert struct.unpack(">Q", e[nfnl.NFTA_SET_ELEM_TIMEOUT]) == (ms,)
                ops.append(("add", name, key, ms / 1000))
        if self.refuse is not None:
            return self.refuse
        for op in ops:
            if op[0] == "flush":
                self.sets[op[1]].clear()
            else:
                self.sets[op[1]][op[2]] = self.clock() + op[3]
        self.transactions.append(ops)
        return 0

    def holding(self) -> list[str]:
        """The states whose set holds the TV's address now: the kernel matches no element past its expiry."""
        if self.sets is None:
            return []
        now = self.clock()
        return [st for st, name in attention.STATE_SETS.items() if self.sets[name].get(TV, -1) > now]

    def left(self, state: str) -> float:
        return self.sets[attention.STATE_SETS[state]][TV] - self.clock()


class Bench:
    """A holder, the kernel's sets, and a live reading whose word the test sets, all on one steady clock."""

    def __init__(self):
        self.now = 1000.0
        self.word: tuple[str | None, float] | None = None
        self.kernel = Kernel(lambda: self.now)
        self.logged: list[str] = []
        self.holder = attention.Holder(
            self.kernel.transact, TV, read=lambda: self.word, clock=lambda: self.now, log=self.logged.append
        )

    def say(self, state: str | None) -> None:
        self.word = (state, self.now)

    def run(self, seconds: float, speak: bool = True, hold: bool = True) -> None:
        """`seconds` of the service: the live reading writes its word every WRITE_EVERY (when `speak`), the
        holder ticks every POLL (when `hold`)."""
        end = self.now + seconds
        while self.now < end - 1e-9:
            self.now = round(self.now + attention.POLL, 6)
            if speak and self.word is not None and self.now - self.word[1] >= attention.WRITE_EVERY:
                self.word = (self.word[0], self.now)
            if hold:
                self.holder.tick()
            assert len(self.kernel.holding()) <= 1, self.kernel.holding()


def test_the_tvs_state_reaches_the_kernel_within_a_poll_and_is_renewed_while_the_word_holds():
    b = Bench()
    b.holder.tick()  # the first tick writes every set: none holds the TV
    assert b.kernel.holding() == [] and b.kernel.transactions[0] == [
        ("flush", name) for name in attention.STATE_SETS.values()
    ]
    b.say(attention.IDLE)
    b.run(attention.POLL)
    assert b.kernel.holding() == [attention.IDLE]
    assert b.kernel.left(attention.IDLE) == pytest.approx(attention.HOLD)
    b.run(60)  # a minute of the screen saver: renewed, never let go
    assert b.kernel.holding() == [attention.IDLE]
    # each renewal is a new element (flushed and added in one transaction): a whole lifetime on any kernel
    assert all(ops[-1][:2] == ("add", "idle4") and len(ops) == 5 for ops in b.kernel.transactions[1:])
    assert b.kernel.left(attention.IDLE) > attention.HOLD - attention.RENEW_EVERY - attention.POLL
    assert b.holder.stats.renewals >= 60 / attention.RENEW_EVERY - 2 and b.holder.stats.failures == 0


def test_a_change_moves_the_address_in_one_transaction_and_never_holds_two_states():
    b = Bench()
    b.say(attention.IDLE)
    b.run(5)
    b.say(attention.APP)  # the viewer came back: by event, under a second, never by waiting for a timeout
    b.run(attention.POLL)
    assert b.kernel.holding() == [attention.APP]
    last = b.kernel.transactions[-1]
    assert [op[:2] for op in last] == [("flush", n) for n in attention.STATE_SETS.values()] + [
        ("add", "app4")
    ]


def test_a_live_reading_that_stops_speaking_leaves_the_tv_in_no_state_within_fresh_seconds():
    b = Bench()
    b.say(attention.INPUT)
    b.run(10)
    b.run(attention.FRESH + attention.POLL, speak=False)  # the live reading died, hung or lost the TV
    assert b.kernel.holding() == []
    assert b.holder.stats.stale == 1 and any("stale" in line for line in b.logged)


def test_a_holder_that_stops_leaves_the_tv_in_no_state_by_the_kernels_clock_within_hold_seconds():
    """The dead-man entry: nobody renews it, and within its lifetime the rules match nothing."""
    b = Bench()
    b.say(attention.IDLE)
    b.run(10)
    b.run(attention.HOLD - attention.RENEW_EVERY - attention.POLL, hold=False)  # killed: no tick at all
    assert b.kernel.holding() == [attention.IDLE]  # not yet: the last renewal's lifetime runs
    b.run(attention.RENEW_EVERY + attention.POLL, hold=False)
    assert b.kernel.holding() == []


def test_a_word_from_the_future_or_none_at_all_holds_nothing():
    b = Bench()
    b.word = (attention.IDLE, b.now + 30)  # not this clock's: no word
    b.run(1)
    assert b.kernel.holding() == []
    b.word = None
    b.run(1)
    assert b.kernel.holding() == []
    b.say(None)  # the live reading speaks and knows no state
    b.run(1)
    assert b.kernel.holding() == []


def test_a_refused_change_is_tried_again_later_and_the_sets_written_whole_when_the_table_comes_back():
    b = Bench()
    b.kernel.sets = None  # an apply between its loads, or ATTENTION_WALL=off applied
    b.say(attention.IDLE)
    b.run(attention.RETRY_EVERY - attention.POLL)
    assert b.holder.stats.failures == 1  # once, not four times a second
    assert any("not loaded" in line for line in b.logged)
    b.kernel.load()
    b.run(attention.RETRY_EVERY)
    assert b.kernel.holding() == [attention.IDLE] and b.holder.held == attention.IDLE


def test_a_table_made_again_empty_gets_the_address_back_at_the_next_renewal():
    b = Bench()
    b.say(attention.INPUT)
    b.run(5)
    b.kernel.load()  # tvgw-apply made the table again (a set of other properties): every set empty
    assert b.kernel.holding() == []
    b.run(attention.RENEW_EVERY + attention.POLL)
    assert b.kernel.holding() == [attention.INPUT]


def test_another_error_is_said_by_name_and_retried():
    b = Bench()
    b.kernel.refuse = errno.ENOMEM
    b.say(attention.IDLE)
    b.run(1)
    assert b.kernel.holding() == [] and any("ENOMEM" in line for line in b.logged)
    b.kernel.refuse = None
    b.run(attention.RETRY_EVERY)
    assert b.kernel.holding() == [attention.IDLE]


def test_clear_empties_every_set():
    b = Bench()
    b.say(attention.LIVETV)
    b.run(2)
    assert b.holder.clear() == 0 and b.kernel.holding() == [] and b.holder.held is None


def test_whatever_the_reading_and_the_holder_do_the_tv_is_never_in_two_states_nor_held_without_a_word():
    """A property over random histories (fixed seeds): the live reading changes state, falls silent or
    dies; the holder runs or is stopped; the table is made again. At every poll at most one state holds
    the TV, and a state is held only if the live reading named it in the last FRESH + HOLD seconds."""
    for seed in range(40):
        rnd = random.Random(seed)
        b = Bench()
        named: dict[str, float] = {}  # state -> the last time the word named it
        for _ in range(60):
            action = rnd.random()
            if action < 0.5:
                b.say(rnd.choice([*attention.STATES, None]))
            elif action < 0.6:
                b.kernel.load()
            elif action < 0.65:
                b.kernel.sets = None
            elif action < 0.7:
                b.kernel.load()
            speak, hold = rnd.random() > 0.2, rnd.random() > 0.2
            for _ in range(rnd.randint(1, 40)):
                b.run(attention.POLL, speak=speak, hold=hold)
                if b.word is not None and b.word[0] is not None:  # when the word last named its state
                    named[b.word[0]] = max(named.get(b.word[0], -1e9), b.word[1])
                for st in b.kernel.holding():
                    assert b.now - named.get(st, -1e9) <= attention.FRESH + attention.HOLD, (seed, st)


def test_the_holders_status_names_its_counts_and_the_state_for_root_alone(tmp_path):
    b = Bench()
    b.say(attention.IDLE)
    b.run(3)
    doc = b.holder.status(started=T0, wall=T0 + 3)
    assert doc["held"] == attention.IDLE and doc["word_fresh"] and doc["stats"]["changes"] == 1
    path = tmp_path / "status.json"
    assert attention.write_status(str(path), doc)
    assert oct(path.stat().st_mode & 0o777) == "0o640"
    assert attention.read_status(str(path), now=T0 + 10)["held"] == attention.IDLE
    assert attention.read_status(str(path), now=T0 + 3 + attention.STATUS_STALE + 1) is None
    assert not attention.write_status(str(tmp_path / "nowhere" / "status.json"), doc)


def test_the_service_exits_at_once_where_the_count_is_not_in_use(capsys, monkeypatch):
    monkeypatch.setattr(attention, "_notify", lambda state: None)
    assert attention.main(Settings()) == 0
    assert "LIVE_READING=off: nothing to hold" in capsys.readouterr().out


# ---- the live reading says the state ------------------------------------------------------------------
def test_a_session_says_the_state_the_tv_reports_and_none_when_it_ends(tmp_path):
    from test_tvlive import Bench as LiveBench
    from test_tvlive import push, serve

    said: list[str | None] = []

    class Said(LiveBench):
        def env(self, port):
            env = super().env(port)
            env.attend = said.append
            return env

    pushes = [
        push("power", state="Active", subscribed=True),
        push("app", appId="com.webos.app.hdmi1", subscribed=True),
        push("power", state="Screen Saver"),
        push("power", state="Active"),
        push("app", appId="netflix"),
        push("power", state="Active", processing="Request Power Off"),
    ]
    b = Said(tmp_path, lambda c: serve(c, pushes))
    b.go()
    changes = [s for i, s in enumerate(said) if i == 0 or said[i - 1] != s]
    assert changes == [
        None,
        attention.INPUT,
        attention.IDLE,
        attention.INPUT,
        attention.APP,
        None,
    ] or changes == [attention.INPUT, attention.IDLE, attention.INPUT, attention.APP, None]


# ---- the essentials -----------------------------------------------------------------------------------
def test_the_essentials_are_the_profiles_platform_names(lg):
    essential = attention.platform_check(lg)
    assert essential("snu.lge.com")  # firmware, a must-allow host
    assert essential("us.lgtvsdp.com") and essential("US.LGTVSDP.COM.")  # the clock
    assert essential("lgtvonline.lge.com")
    assert not essential("pubads.g.doubleclick.net")  # advertising
    assert not essential("us.ad.lgsmartad.com")  # LG's own advertising is no essential
    assert not essential("rr3---sn-x.googlevideo.com")  # video is an app's, not the TV's
    assert not essential("") and not essential(None)


def test_the_passive_feeders_script_for_the_essentials_names_the_attention_table():
    assert attention.platform_batch(["192.0.2.7"], 86400) == (
        "add element inet tvgw_attn platform4 { 192.0.2.7 timeout 86400s expires 86400s }\n"
    )


def answer(name: str, *addrs: str, rcode_flags: int = 0x8180) -> bytes:
    """A DNS answer for `name` with A records, compressed against the question as resolvers write it."""
    head = struct.pack(">HHHHHH", 0x1234, rcode_flags, 1, len(addrs), 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
    rr = b"".join(
        struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + bytes(int(x) for x in a.split(".")) for a in addrs
    )
    return head + q + rr


def test_the_question_names_what_the_tv_looked_up():
    assert dnsmsg.qname(answer("snu.lge.com", "192.0.2.1")) == "snu.lge.com"
    assert dnsmsg.qname(b"\x00" * 11) is None
    assert dnsmsg.qname(struct.pack(">HHHHHH", 1, 0x8180, 0, 0, 0, 0)) is None  # no question
    assert dnsmsg.qname(struct.pack(">HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\x05ab") is None  # cut short


def udp(payload: bytes) -> bytes:
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + 8 + len(payload), 0, 0, 64, 17, 0, bytes(4), bytes(4))
    return ip + struct.pack(">HHHH", 53, 40000, 8 + len(payload), 0) + payload


def test_the_in_path_reader_marks_the_addresses_of_an_answer_to_an_essential(lg):
    essential = attention.platform_check(lg)
    got = inpath.read_packet(udp(answer("snu.lge.com", "192.0.2.1", "192.0.2.2")), essential=essential)
    assert got.addrs == got.essential == (bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    other = inpath.read_packet(udp(answer("pubads.g.doubleclick.net", "192.0.2.9")), essential=essential)
    assert other.addrs == (bytes([192, 0, 2, 9]),) and other.essential == ()
    assert inpath.read_packet(udp(answer("snu.lge.com", "192.0.2.1"))).essential == ()  # no test: none


def test_a_test_that_raises_marks_nothing_and_keeps_no_answer():
    def broken(name):
        raise RuntimeError("profile gone")

    got = inpath.read_packet(udp(answer("snu.lge.com", "192.0.2.1")), essential=broken)
    assert got.kind == inpath.ANSWER and got.essential == ()


class Adder:
    """The filler's adder, run at once, with the two transactions recorded and their answers chosen."""

    def __init__(self, essential_errno: int = 0):
        self.gate: list[tuple] = []
        self.essentials: list[tuple] = []
        self.essential_errno = essential_errno

    def submit(self, addrs, essential=()):
        job = inpath.Job(addrs, essential=essential)
        job.errno = 0
        if addrs:
            self.gate.append(addrs)
        if essential:
            self.essentials.append(essential)
            job.essential_errno = self.essential_errno
        job.done.set()
        return job


def filler(lg, adder, released, now=None):
    clock = (lambda: now[0]) if now is not None else (lambda: 0.0)
    return inpath.Filler(released.append, adder, clock=clock, essential=attention.platform_check(lg))


def test_the_filler_adds_an_essentials_addresses_before_it_releases_the_answer(lg):
    adder, released = Adder(), []
    f = filler(lg, adder, released)
    f.handle(nfnl.Packet(1, 3, udp(answer("snu.lge.com", "192.0.2.1"))), 0.0)
    assert released == [1] and adder.gate == adder.essentials == [(bytes([192, 0, 2, 1]),)]
    assert f.stats.held == 1 and f.stats.essentials == 1
    # the same address again for another name: known to the gate, and no essential
    f.handle(nfnl.Packet(2, 3, udp(answer("tracker.example", "192.0.2.1"))), 0.1)
    assert released == [1, 2] and len(adder.gate) == 1 and f.stats.known == 1
    # an address the gate knows, now answered for an essential: added there, and the answer held for it
    f.handle(nfnl.Packet(3, 3, udp(answer("tracker.example", "192.0.2.5"))), 0.2)
    f.handle(nfnl.Packet(4, 3, udp(answer("snu.lge.com", "192.0.2.5"))), 0.3)
    assert adder.essentials[-1] == (bytes([192, 0, 2, 5]),) and adder.gate[-1] == (bytes([192, 0, 2, 5]),)
    assert len(adder.gate) == 2 and released == [1, 2, 3, 4]
    # the fourth waited for its essentials alone: counted apart, and every hold that added essentials is
    # measured apart from the gate's own
    assert (f.stats.held, f.stats.held_essentials) == (2, 1)
    assert len(f.holds) == 1 and len(f.essential_holds) == 2
    doc = inpath.status(f, inpath.QUEUE, True, 0.0, 1.0)
    assert doc["hold_us"]["n"] == 1 and doc["essential_hold_us"]["n"] == 2


def test_a_missing_attention_table_never_costs_the_gate_its_add_and_waits_before_trying_again(lg):
    adder, released, now = Adder(essential_errno=errno.ENOENT), [], [0.0]
    f = filler(lg, adder, released, now)
    f.handle(nfnl.Packet(1, 3, udp(answer("snu.lge.com", "192.0.2.1"))), 0.0)
    assert released == [1] and f.stats.held == 1 and f.stats.failed == 0  # the gate's add counts as held
    assert f.stats.essentials_failed == 1 and not f.set_missing  # the gate's own set is not missing
    f.handle(nfnl.Packet(2, 3, udp(answer("snu.lge.com", "192.0.2.2"))), 0.1)
    assert len(adder.essentials) == 1  # no second try within ESSENTIALS_OFF
    now[0] = inpath.ESSENTIALS_OFF + 0.5
    f.handle(nfnl.Packet(3, 3, udp(answer("snu.lge.com", "192.0.2.3"))), 0.2)
    assert len(adder.essentials) == 2


def test_the_real_adder_runs_the_essentials_add_after_the_gates_and_apart_from_it():
    calls = []
    a = inpath.Adder(lambda addrs: calls.append(("gate", addrs)) or 0, add_essential=lambda addrs: 2)
    a.start()
    job = a.submit((b"\xc0\x00\x02\x01",), essential=(b"\xc0\x00\x02\x01",))
    assert job.done.wait(2) and job.errno == 0 and job.essential_errno == errno.ENOENT
    only = a.submit((), essential=(b"\xc0\x00\x02\x02",))
    assert only.done.wait(2) and only.errno == 0 and calls == [("gate", (b"\xc0\x00\x02\x01",))]


def test_the_passive_feeder_sends_an_essentials_addresses_to_the_attention_table_in_a_run_of_its_own(lg):
    from tvgw import dnsgate

    frames = [answer("snu.lge.com", "192.0.2.1"), answer("pubads.g.doubleclick.net", "192.0.2.9")]
    scripts, logged = [], []

    def nft(script):
        scripts.append(script)
        return 1 if "tvgw_attn" in script else 0

    pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for f in frames:
        eth = b"\x00" * 12 + b"\x08\x00" + udp(f)
        pcap += struct.pack("<IIII", 0, 0, len(eth), len(eth)) + eth
    stream = memoryview(pcap)
    pos = [0]

    def read(n):
        chunk = bytes(stream[pos[0] : pos[0] + n])
        pos[0] += len(chunk)
        return chunk

    dnsgate.feed(read, nft, log=logged.append, clock=lambda: 1000.0, essential=attention.platform_check(lg))
    assert scripts == [
        dnsgate.batch(["192.0.2.1"]),
        attention.platform_batch(["192.0.2.1"], dnsgate.TTL),
        dnsgate.batch(["192.0.2.9"]),
    ]
    assert len(logged) == 1 and "tvgw_attn" in logged[0]  # refused, and said once


# ---- the samples --------------------------------------------------------------------------------------
def listing(*elems, set_name="idle_seen4", timeout=10800) -> str:
    return json.dumps(
        {
            "nftables": [
                {"metainfo": {"version": "1.1.3"}},
                {"table": {"family": "inet", "name": "tvgw_attn"}},
                {"set": {"family": "inet", "table": "tvgw_attn", "name": "platform4", "elem": ["192.0.2.1"]}},
                {
                    "set": {
                        "family": "inet",
                        "table": "tvgw_attn",
                        "name": set_name,
                        "timeout": timeout,
                        "elem": list(elems),
                    }
                },
            ]
        }
    )


def elem(dst, proto, sport, dport, expires, timeout=None):
    e = {"val": {"concat": [dst, proto, sport, dport]}, "expires": expires}
    if timeout is not None:
        e["timeout"] = timeout
    return {"elem": e}


def test_a_sample_is_read_with_the_time_the_kernel_first_counted_it():
    text = listing(
        elem("203.0.113.9", "tcp", 51234, 443, 10800 - 600),
        elem("203.0.113.10", 17, "40001", "5000", 9000, timeout=10800),
    )
    found = attention.samples_from_listing(text, T0)
    assert found == [
        attention.Sample(T0 - 600, attention.IDLE, "tcp", "203.0.113.9", 51234, 443),
        attention.Sample(T0 - 1800, attention.IDLE, "udp", "203.0.113.10", 40001, 5000),
    ]
    inputs = attention.samples_from_listing(
        listing(elem("203.0.113.9", "tcp", 1, 2, 3), set_name="input_seen4"), T0
    )
    assert [s.state for s in inputs] == [attention.INPUT]


@pytest.mark.parametrize(
    "bad",
    [
        elem("not an address", "tcp", 1, 2, 3),
        elem("203.0.113.9", "icmp", 1, 2, 3),
        elem("203.0.113.9", "tcp", 70000, 2, 3),
        elem("203.0.113.9", "tcp", True, 2, 3),
        {"elem": {"val": {"concat": ["203.0.113.9", "tcp", 1]}, "expires": 3}},
        {"elem": {"val": "203.0.113.9", "expires": 3}},
        {"elem": {"val": {"concat": ["203.0.113.9", "tcp", 1, 2]}}},  # no expiry
        "203.0.113.9",
    ],
)
def test_anything_that_is_not_exactly_a_sample_is_skipped(bad):
    assert attention.samples_from_listing(listing(bad), T0) == []


def test_a_listing_that_is_not_one_reads_as_no_samples():
    assert attention.samples_from_listing("", T0) == []
    assert attention.samples_from_listing("{not json", T0) == []
    assert (
        attention.samples_from_listing(listing(elem("203.0.113.9", "tcp", 1, 2, 3), set_name="conn4"), T0)
        == []
    )


@pytest.fixture
def conn(tmp_path):
    c = db.connect(str(tmp_path / "tvgw.db"))
    yield c
    c.close()


def test_a_sample_read_again_in_a_later_hour_is_stored_once(conn):
    one = attention.Sample(T0, attention.IDLE, "tcp", "203.0.113.9", 51234, 443)
    assert attention.store_samples(conn, [one]) == 1
    again = attention.Sample(T0 + 1, attention.IDLE, "tcp", "203.0.113.9", 51234, 443)  # its expiry rounded
    assert attention.store_samples(conn, [again]) == 0
    other = attention.Sample(T0 + 1, attention.IDLE, "tcp", "203.0.113.9", 51235, 443)
    later = attention.Sample(T0 + 3600, attention.IDLE, "tcp", "203.0.113.9", 51234, 443)
    assert attention.store_samples(conn, [other, later]) == 2
    assert conn.execute("SELECT COUNT(*) FROM attention").fetchone()[0] == 3


def test_the_ingest_step_stores_what_the_kernel_holds_and_nothing_where_the_table_is_not_loaded(conn):
    text = listing(elem("203.0.113.9", "tcp", 51234, 443, 10000))
    assert attention.ingest_samples(conn, listing=lambda: text, now=lambda: T0) == 1
    later = listing(elem("203.0.113.9", "tcp", 51234, 443, 6401))  # an hour on, a second's rounding apart
    assert attention.ingest_samples(conn, listing=lambda: later, now=lambda: T0 + 3600) == 0
    assert attention.ingest_samples(conn, listing=lambda: "", now=lambda: T0) == 0


def test_the_table_listing_is_empty_where_nft_says_there_is_no_table():
    class Done:
        def __init__(self, rc, out):
            self.returncode, self.stdout = rc, out

    assert attention.list_table(lambda *a, **k: Done(1, "")) == ""
    assert attention.list_table(lambda *a, **k: Done(0, "{}")) == "{}"

    def missing(*a, **k):
        raise FileNotFoundError("nft")

    assert attention.list_table(missing) == ""


def test_the_samples_and_the_counters_are_kept_as_long_as_the_live_record_and_forgotten_with_it(conn):
    old, new = T0 - 20 * 86400, T0 - 86400
    for t in (old, new):
        conn.execute(
            "INSERT INTO attention(t, state, proto, dst, sport, dport) VALUES (?,?,?,?,?,?)",
            (t, attention.IDLE, "tcp", "203.0.113.9", 1, 443),
        )
        for rule in (attention.RULES[attention.IDLE], "DoH resolvers"):
            conn.execute("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)", (t, rule, 1, 0))
    ingest.prune(conn, days=30, now=T0, tv_events_days=14)
    assert [r[0] for r in conn.execute("SELECT t FROM attention")] == [new]
    kept = conn.execute("SELECT rule, t FROM fw_counters ORDER BY rule, t").fetchall()
    assert kept == [
        ("DoH resolvers", old),  # every other counter keeps DB_DAYS
        ("DoH resolvers", new),
        (attention.RULES[attention.IDLE], new),
    ]
    from tvgw import forget

    assert "attention" in forget.TABLES and forget.TIME_COLUMNS["attention"] == "t"
    assert "attention" in db.TABLES and db.SCHEMA_VERSION == 14


# ---- the report ---------------------------------------------------------------------------------------
def ev(t, kind, value="", detail=""):
    return appfront.Event(t, kind, value, detail)


def test_the_window_is_cut_by_the_live_records_events_into_states():
    events = [
        ev(90, "conn", "up"),
        ev(91, "power", "Active"),
        ev(91, "app", "netflix"),
        ev(150, "power", "Screen Saver"),
        ev(300, "power", "Active"),
        ev(320, "app", "com.webos.app.hdmi1"),
        ev(400, "conn", "down", "lost"),
        ev(500, "conn", "up"),
        ev(501, "power", "Active"),
        ev(502, "app", "com.webos.app.livetv"),
    ]
    assert attention.intervals(events, 100, 600) == [
        (100, 150, attention.APP),
        (150, 300, attention.IDLE),
        (300, 320, attention.APP),
        (320, 400, attention.INPUT),
        (502, 600, attention.LIVETV),
    ]
    assert attention.intervals(events, 160, 200) == [(160, 200, attention.IDLE)]


def flow(conn, t, dst, sport, dport=443, name=None, up=1000, down=9000):
    conn.execute(
        "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, pkts_up, bytes_up, pkts_down, bytes_down)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (t, t + 30, "tcp", dst, dport, sport, 10, up, 10, down),
    )
    if name:
        conn.execute(
            "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (?,?,?,?,?)",
            (t + 0.1, dst, dport, sport, name),
        )


def sample(conn, t, state, dst, sport, dport=443):
    conn.execute(
        "INSERT INTO attention(t, state, proto, dst, sport, dport) VALUES (?,?,?,?,?,?)",
        (t, state, "tcp", dst, sport, dport),
    )


def events(conn, rows):
    for t, kind, value in rows:
        conn.execute("INSERT INTO tv_events(t, kind, value, detail) VALUES (?,?,?,'')", (t, kind, value))


@pytest.fixture
def day(conn):
    """One day: the screen saver on from 20:00 to 23:00 behind an app, an HDMI hour before it."""
    a = T0
    events(
        conn,
        [
            (a + 3600, "conn", "up"),
            (a + 3600, "power", "Active"),
            (a + 3600, "app", "com.webos.app.hdmi1"),
            (a + 7200, "app", "youtube.leanback.v4"),
            (a + 8000, "power", "Screen Saver"),
            (a + 18800, "power", "Active"),
        ],
    )
    # under the screen saver: an ad tracker twice, a delivery host, a connection no hello named, and one
    # of the TV's essentials whose address the platform set did not hold
    for i, sport in enumerate((40001, 40002)):
        flow(conn, a + 9000 + i, "203.0.113.20", sport, name="pubads.g.doubleclick.net")
        sample(conn, a + 9000 + i, attention.IDLE, "203.0.113.20", sport)
    flow(conn, a + 9100, "203.0.113.30", 40003, name="rr1.googlevideo.com", down=500_000)
    sample(conn, a + 9100, attention.IDLE, "203.0.113.30", 40003)
    flow(conn, a + 9200, "198.51.100.77", 40004)
    sample(conn, a + 9200, attention.IDLE, "198.51.100.77", 40004)
    conn.execute(
        "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?,?,?,?,0)",
        (a + 9299.5, "snu.lge.com", "A", "A:203.0.113.40"),
    )
    flow(conn, a + 9300, "203.0.113.40", 40005, name="snu.lge.com")
    sample(conn, a + 9300, attention.IDLE, "203.0.113.40", 40005)
    # one second before the screen saver went off: the app the viewer opens, before the TV said so
    flow(conn, a + 18799, "203.0.113.50", 40006, name="api.example-app.tv")
    sample(conn, a + 18799, attention.IDLE, "203.0.113.50", 40006)
    # on the HDMI input: one connection, sampled by the kernel as an input's
    flow(conn, a + 4000, "203.0.113.60", 40007, name="ads.example-ott.com")
    sample(conn, a + 4000, attention.INPUT, "203.0.113.60", 40007)
    for t, n in ((a + 600, 0), (a + 20000, 7)):
        conn.execute(
            "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,0)",
            (t, attention.RULES[attention.IDLE], n),
        )
    return a


def test_the_report_names_the_services_behind_each_states_count_with_its_marks(conn, lg, day):
    rep = attention.report(conn, day, day + 86400, lg, times=True)
    idle = rep["states"][attention.IDLE]
    assert idle["seconds"] == 10800 and idle["counted"] == 7 and idle["samples"] == 6
    by = {x["key"]: x for x in idle["services"]}
    assert by["doubleclick.net"]["conns"] == 2 and by["doubleclick.net"]["cls"] == appfront.TRACKING
    assert by["doubleclick.net"]["company"] == "Google"
    assert by["googlevideo.com"]["bytes"] == 501_000
    assert by["198.51.100.0/24"]["cls"] == appfront.UNCLASSIFIED
    assert by["lge.com"]["essential"] and by["lge.com"]["late"] == 1  # the race, and an essential missed
    assert idle["services"][0]["key"] == "lge.com"  # an essential missed is listed first
    assert by["example-app.tv"]["lead"] == 1 and by["doubleclick.net"]["lead"] == 0
    inp = rep["states"][attention.INPUT]
    assert inp["seconds"] == 3600 and [x["key"] for x in inp["services"]] == ["example-ott.com"]
    assert rep["states"][attention.LIVETV]["seconds"] == 0
    # what the plain line names: neither the essential nor the app that started before the TV said so
    assert rep["outside"] == ["doubleclick.net", "198.51.100.0/24", "example-ott.com", "googlevideo.com"]


def test_a_sample_the_live_record_puts_in_another_state_is_counted_as_the_holders_lag(conn, lg, day):
    sample(conn, day + 7300, attention.IDLE, "203.0.113.70", 40008)  # the record says YouTube in front
    assert attention.report(conn, day, day + 86400, lg)["states"][attention.IDLE]["other_state"] == 1


def test_a_window_without_the_count_has_no_section_at_all(conn, lg):
    assert attention.report(conn, T0, T0 + 86400, lg) is None
    old = sqlite3.connect(":memory:")  # a store from before schema 17
    assert attention._has_data(old, T0, T0 + 86400) is False


def test_a_day_like_the_days_before_it_says_how_many_days_it_has_come(conn, lg):
    from datetime import datetime, timedelta

    first = datetime.fromtimestamp(T0).replace(hour=0, minute=0, second=0, microsecond=0)
    days = [(first + timedelta(days=i)).timestamp() for i in range(5)]
    for i, d in enumerate(days):
        events(conn, [(d + 3600, "conn", "up"), (d + 3600, "power", "Screen Saver")])
        name = "pubads.g.doubleclick.net" if i < 4 else "new-tracker.example"
        flow(conn, d + 4000, "203.0.113.20", 41000 + i, name=name)
        sample(conn, d + 4000, attention.IDLE, "203.0.113.20", 41000 + i)
        events(conn, [(d + 7200, "conn", "down")])
    rep = attention.report(conn, days[3], days[4], lg)
    assert rep["days_running"] == 4 and rep["new_services"] is False
    rep = attention.report(conn, days[4], days[4] + 86400, lg)
    assert rep["days_running"] == 4 and rep["new_services"] is True  # capped at REPEAT_DAYS + 1
    assert attention.report(conn, days[1] + 600, days[2], lg)["days_running"] is None  # not a calendar day


# ---- the brief and the plain line ---------------------------------------------------------------------
def test_the_window_report_carries_the_section_only_where_the_count_ran(conn, lg, day):
    from tvgw import queries

    with_it = queries.window_report(conn, day, day + 86400, lg, gw_ip="10.10.10.1")
    assert with_it["attention"]["states"]["idle"]["samples"] == 6
    # a report tvgw-analyze saves never carries the time in a state: the live record's, kept 14 days
    assert all("seconds" not in st for st in with_it["attention"]["states"].values())
    asked = queries.window_report(conn, day, day + 86400, lg, gw_ip="10.10.10.1", app_in_front=True)
    assert asked["attention"]["states"]["idle"]["seconds"] == 10800  # the interactive brief has it
    assert not [x for x in with_it["firewall"]["activity"] if x["rule"].startswith("attention:")]
    without = queries.window_report(conn, day + 2 * 86400, day + 3 * 86400, lg, gw_ip="10.10.10.1")
    assert "attention" not in without


def test_the_engineering_brief_lists_each_state_and_its_services(conn, lg, day):
    import io

    saved = io.StringIO()
    cli.render_attention(attention.report(conn, day, day + 86400, lg), saved)
    assert "  screen saver on: 7 counted, 6 sampled," in saved.getvalue() and " h " not in saved.getvalue()
    out = io.StringIO()
    cli.render_attention(attention.report(conn, day, day + 86400, lg, times=True), out)
    text = out.getvalue()
    assert text.startswith("\nAttention (count-only; nothing is refused): ")
    assert "  screen saver on: 3 h 00 min; 7 counted, 6 sampled," in text
    assert "lge.com" in text and "ESSENTIAL" in text and "Google" in text
    assert "  an input in front (HDMI or another): 1 h 00 min; 0 counted, 1 sampled," in text
    assert "live TV" not in text  # a state with nothing in it is not printed
    blank = io.StringIO()
    cli.render_attention(None, blank)
    assert blank.getvalue() == ""


def test_the_plain_line_names_the_services_and_says_nothing_was_stopped(conn, lg, day):
    rep = attention.report(conn, day, day + 86400, lg)
    (line,) = plain._attention_note({"attention": rep})
    assert line == (
        "  Screen saver and inputs: While the screen saver was on or an input such as HDMI was in front, the TV reached 4"
        " services outside what it needs to work (doubleclick.net (Google), 198.51.100.0/24,"
        " example-ott.com and 1 more). Nothing was stopped: the gateway is counting."
    )
    for word in ("wall", "platform", "essential", "refuse"):
        assert word not in line.lower()


def test_no_plain_line_without_a_service_or_after_the_days_it_repeats_unchanged():
    assert plain._attention_note({}) == []
    assert plain._attention_note({"attention": {"outside": []}}) == []
    sec = {
        "outside": ["doubleclick.net"],
        "states": {"idle": {"services": [{"key": "doubleclick.net"}]}},
        "days_running": 3,
        "new_services": False,
    }
    (line,) = plain._attention_note({"attention": sec})
    assert line.startswith(
        "  Screen saver and inputs: While the screen saver was on, the TV reached 1 service "
    )
    assert "3 days running" in line
    assert plain._attention_note({"attention": {**sec, "days_running": 4}}) == []
    assert plain._attention_note({"attention": {**sec, "days_running": 4, "new_services": True}})


# ---- the check and the status command -----------------------------------------------------------------
NEEDLES = "\n".join(needle for needle, _ in verify.ATTENTION_NEEDLES)


def check(s, listing, status, now=T0):
    def run(argv):
        return listing if argv[-1] == attention.TABLE else ""

    def read(path):
        return json.dumps(status) if path == attention.STATUS and status is not None else ""

    return verify.attention_check(s, run, read, now)


def test_the_check_passes_saying_so_where_the_count_is_not_in_use():
    c = check(Settings(), "", None)
    assert c.ok and not c.warn and c.detail.startswith("not in use (LIVE_READING=off)")


def test_the_check_warns_at_most_and_never_names_the_tvs_state():
    missing = check(ON, "", None)
    assert missing.ok and missing.warn and missing.detail.startswith("missing: the essentials' set")
    stale = check(ON, NEEDLES, {"t": T0 - 300, "held": "idle"})
    assert stale.ok and stale.warn and "5 min old" in stale.detail.replace("minutes", "min")
    fine = check(ON, NEEDLES, {"t": T0 - 5, "started": T0 - 7200, "held": "idle"})
    assert fine.ok and not fine.warn and fine.detail.startswith("loaded, and its holder runs")
    refuse = check(Settings(live_reading="on", attention_wall="refuse"), NEEDLES, {"t": T0, "held": None})
    assert "not supported on a live gateway yet" in refuse.detail
    # whatever state the holder holds, the detail is the same: it reaches the public hardware log
    for held in ("app", "input", None):
        assert check(ON, NEEDLES, {"t": T0 - 5, "started": T0 - 7200, "held": held}).detail == fine.detail
        assert check(ON, NEEDLES, {"t": T0 - 300, "held": held}).detail == stale.detail
    assert verify.FAIL_AFTER["attention"] == verify.WARN


def test_the_status_says_what_is_held_and_what_was_counted():
    sets = json.loads(listing(elem("203.0.113.9", "tcp", 1, 2, 3)))
    lines = attention.status_lines(
        ON, {"t": T0, "started": T0 - 60, "held": "idle", "stats": {}}, json.dumps(sets)
    )
    assert lines[0] == "LIVE_READING=on, PROFILE=lg-webos, ATTENTION_WALL=count"
    assert "the firewall holds the live reading's word now: the screen saver is on" in lines
    assert "essential addresses the gateway knows: 1" in lines
    assert "connections counted in the last 3 hours, by state: screen saver 1, input 0, live TV 0" in lines
    off = attention.status_lines(Settings(), None, "")
    assert off[-1] == "the attention count is not in use (LIVE_READING=off): nothing is held or counted"
    down = attention.status_lines(Settings(live_reading="on", attention_wall="refuse"), None, "")
    assert any("not supported on a live gateway yet" in x for x in down)
    assert any(x.startswith("the holder is not running") for x in down) and "is not loaded" in down[-1]


def test_the_status_command_asks_for_root_rather_than_say_the_holder_is_down(monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    assert cli.cmd_attention(None, ON, None) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == [
        "LIVE_READING=on, PROFILE=lg-webos, ATTENTION_WALL=count",
        "the holder's status and the firewall's table are root's: run sudo tvgw attention",
    ]
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(attention, "read_status", lambda: None)
    monkeypatch.setattr(attention, "list_table", lambda: "")
    assert cli.cmd_attention(None, ON, None) == 0
    assert "the holder is not running" in capsys.readouterr().out


def test_the_word_is_read_from_a_regular_file_only_never_through_a_link_or_a_fifo(tmp_path):
    import os

    real = tmp_path / "attention"
    attention.write_word(str(real), attention.IDLE, 5.0)
    link = tmp_path / "link"
    link.symlink_to(real)
    assert attention.read_word(str(real)) == (attention.IDLE, 5.0)
    assert attention.read_word(str(link)) is None
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert attention.read_word(str(fifo)) is None  # at once: nobody writes, and the read must not wait
    # a FIFO that does hold a word is still no word: only a regular file is the live reading's
    keep = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)  # a reader, so that the writer may open
    writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
    try:
        os.write(writer, attention.encode_word(attention.IDLE, 5.0))
        assert attention.read_word(str(fifo)) is None
    finally:
        os.close(writer)
        os.close(keep)
    assert attention.read_word(str(tmp_path)) is None  # a directory


def test_the_passive_feeder_fills_the_essentials_only_where_it_is_the_gates_one_filler(lg):
    from tvgw import dnsgate

    assert dnsgate.essential_test(ON, lg) is not None
    assert dnsgate.essential_test(Settings(live_reading="on", dnsgate_fill="inpath"), lg) is None
    assert dnsgate.essential_test(Settings(), lg) is None
    assert dnsgate.essential_test(ON, None) is None


def feed_frames(frames: list[bytes]):
    pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for f in frames:
        eth = b"\x00" * 12 + b"\x08\x00" + udp(f)
        pcap += struct.pack("<IIII", 0, 0, len(eth), len(eth)) + eth
    pos = [0]

    def read(n):
        chunk = pcap[pos[0] : pos[0] + n]
        pos[0] += len(chunk)
        return chunk

    return read


def test_the_passive_feeder_adds_an_essentials_address_once_in_ten_seconds_and_backs_off_after_a_refusal(lg):
    from tvgw import dnsgate

    now = [100.0]
    scripts: list[str] = []
    refuse = [False]

    def nft(script):
        scripts.append(script)
        now[0] += 1.0  # each answer a second after the one before
        return 1 if refuse[0] and "tvgw_attn" in script else 0

    snu = answer("snu.lge.com", "192.0.2.1")
    essential = attention.platform_check(lg)
    dnsgate.feed(feed_frames([snu, snu, snu]), nft, essential=essential, mono=lambda: now[0])
    platform = [x for x in scripts if "tvgw_attn" in x]
    assert len(platform) == 1  # added once: known for ESSENTIALS_KNOWN seconds after
    scripts.clear()
    now[0] += dnsgate.ESSENTIALS_KNOWN
    refuse[0] = True
    logged: list[str] = []
    dnsgate.feed(
        feed_frames([answer("snu.lge.com", "192.0.2.7")] * 4),
        nft,
        log=logged.append,
        essential=essential,
        mono=lambda: now[0],
    )
    assert len([x for x in scripts if "tvgw_attn" in x]) == 1  # refused once, then none for ESSENTIALS_OFF
    assert len([x for x in scripts if "tvgw_gate" in x]) == 4  # the gate's own adds, every one
    assert len(logged) == 1


def test_forget_removes_the_attention_counters_and_keeps_every_other_counter(tree):  # noqa: F811
    from test_forget import live

    from tvgw import forget

    conn = db.connect(tree.db_path)
    for rule in (attention.RULES[attention.IDLE], "DoH resolvers"):
        conn.execute("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,1,0)", (T0, rule))
    conn.commit()
    conn.close()
    plan = forget.run(tree, dry_run=True, live=live(tree))
    assert any(
        st.action == "delete-rows" and st.what.startswith("fw_counters (") and st.count == 1
        for st in plan.steps
    )
    forget.run(tree, live=live(tree), lock=False)
    conn = db.connect(tree.db_path, readonly=True)
    rules = [r[0] for r in conn.execute("SELECT rule FROM fw_counters")]
    conn.close()
    assert "DoH resolvers" in rules and not [r for r in rules if r.startswith(attention.RULE_PREFIX)]
