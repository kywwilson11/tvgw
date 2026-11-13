"""(mint) The minting table's promises (design decision 85) over every order of answers, waits, sweeps and
revocations hypothesis can find, against a model that is slow and plain: the live pairs, and the moment
each address's last ticket ended. Seven addresses, three names of three addresses each and a share of
two, with waits that land on the lifetime and the rest to the second: a full pool, a rest, a name over
its share and a ticket answered again ahead of an older one are all reached within a few steps."""

import ipaddress

import pytest

pytest.importorskip("hypothesis")  # the dev extras carry it
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from tvgw import mint

POOL = ipaddress.ip_network("198.18.0.248/29")  # .248 to .254, and .255, which is never given out
ADDRESSES = [a.packed for a in POOL if mint.given_out(int(a))]
NAMES = [f"n{i}.example" for i in range(3)]
REALS = [bytes([203, 0, 113, i]) for i in range(1, 4)]
LIFE, REST, SHARE = 100.0, 300.0, 2


class Table(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.table = mint.Minter(POOL, lifetime=LIFE, rest=REST, per_name=SHARE)
        self.now = 0.0
        self.live: dict[tuple[str, bytes], tuple[bytes, float]] = {}  # pair -> (address, last answered)
        self.ended: dict[bytes, float] = {}  # address -> when its last ticket ended
        self.kernel: dict[bytes, tuple[bytes, float]] = {}  # the kernel's map: address -> (real, until)
        self.answers = 0

    # ---- the model -------------------------------------------------------------------------------------
    def end(self, pair: tuple[str, bytes], at: float) -> None:
        self.ended[self.live.pop(pair)[0]] = at

    def held(self, name: str) -> dict[bytes, float]:
        """real -> last answered, for the name's live pairs."""
        return {real: answered for (n, real), (_address, answered) in self.live.items() if n == name}

    def owed(self) -> set[bytes]:
        """The addresses a new pair may get now: the first nobody has held, else whichever has rested
        longest, once that is REST. Empty when the answer must go without a ticket."""
        busy = {address for address, _answered in self.live.values()}
        unused = [a for a in ADDRESSES if a not in busy and a not in self.ended]
        if unused:
            return {unused[0]}
        resting = {a: at for a, at in self.ended.items() if a not in busy}
        longest = min(resting.values(), default=self.now)
        return {a for a, at in resting.items() if at == longest and self.now - at >= REST}

    def to_kernel(self, ops: list[mint.Op]) -> None:
        for op in ops:
            if op.kind == mint.ADD:
                self.kernel[op.minted] = (op.real, self.now + op.timeout)
            else:
                del self.kernel[op.minted]  # a delete of an element the kernel never had is a bug too

    # ---- what can happen -------------------------------------------------------------------------------
    @rule(seconds=st.sampled_from([1.0, 40.0, LIFE - 40.0, REST - LIFE]))
    def wait(self, seconds):
        self.now += seconds
        for pair, (_address, answered) in list(self.live.items()):
            if answered + LIFE <= self.now:
                self.end(pair, answered + LIFE)

    @rule()
    def sweep(self):
        self.table.expire(self.now)
        assert len(self.table) == len(self.live)

    @rule(name=st.sampled_from(NAMES), real=st.sampled_from(REALS))
    def answer(self, name, real):
        self.answers += 1
        pair, share, owed = (name, real), self.held(name), self.owed()
        ticket, ops = self.table.mint(name, real, self.now)
        if pair in self.live:  # answered again: the same address, a full lifetime from now
            evicted, owed = [], {self.live[pair][0]}
        elif not owed:  # no address may be given: no ticket, and nothing changed
            assert (ticket, ops) == (None, [])
            return
        else:  # a new pair; its name, if over its share, loses its least recently answered ticket
            evicted = [op.minted for op in ops if op.kind == mint.DEL]
            assert len(evicted) == (len(share) == SHARE)
            for address in evicted:
                (lost,) = (r for r in share if self.live[name, r][0] == address)
                assert share[lost] == min(share.values())
                self.end((name, lost), self.now)
        assert ticket.minted in owed
        assert ops == [mint.Op(mint.DEL, a) for a in evicted] + [mint.Op(mint.ADD, ticket.minted, real, LIFE)]
        assert (ticket.name, ticket.real, ticket.expires) == (name, real, self.now + LIFE)
        self.live[pair] = (ticket.minted, self.now)
        self.to_kernel(ops)

    @rule(name=st.sampled_from(NAMES))
    def revoke(self, name):
        share = self.held(name)
        gone, ops = self.table.revoke(name, self.now)
        assert sorted(t.real for t in gone) == sorted(share) and {t.name for t in gone} <= {name}
        assert ops == [mint.Op(mint.DEL, t.minted) for t in gone]
        for real in share:
            self.end((name, real), self.now)
        self.to_kernel(ops)

    # ---- what always holds -----------------------------------------------------------------------------
    @invariant()
    def the_table_holds_the_live_pairs_each_at_its_own_address(self):
        alive = {p: (t.minted, t.answered) for p, t in self.table.by_pair.items() if t.expires > self.now}
        assert alive == self.live
        assert len({address for address, _answered in self.live.values()}) == len(self.live)

    @invariant()
    def every_view_holds_the_same_tickets(self):
        t = self.table
        by_name = {(name, real): x for name, held in t.by_name.items() for real, x in held.items()}
        by_real = {(name, real): x for real, held in t.by_real.items() for name, x in held.items()}
        by_minted = {(x.name, x.real): x for x in t.by_minted.values()}
        assert dict(t.by_pair) == by_name == by_real == by_minted and len(t.by_minted) == len(t.by_pair)
        assert all(0 < len(held) <= SHARE for held in t.by_name.values()) and all(t.by_real.values())

    @invariant()
    def the_kernel_s_map_agrees_though_nobody_tells_it_a_ticket_ran_out(self):
        alive = {address: real for address, (real, until) in self.kernel.items() if until > self.now}
        assert alive == {address: real for (_name, real), (address, _answered) in self.live.items()}

    @invariant()
    def an_address_means_its_live_ticket_and_nothing_else(self):
        for real in REALS:
            assert sorted(self.table.names_of(real, self.now)) == sorted(n for n, r in self.live if r == real)
        by_address = {address: pair for pair, (address, _answered) in self.live.items()}
        for address in ADDRESSES:
            found = self.table.lookup(address, self.now)
            assert (found and (found.name, found.real)) == by_address.get(address)

    @invariant()
    def the_counts_add_up(self):
        c, held = self.table.counts, [len(h) for h in self.table.by_name.values()]
        assert c.minted + c.renewed + c.refused == self.answers
        assert c.minted - c.expired - c.revoked - c.evicted == len(self.table)
        assert len(self.live) <= len(self.table) <= c.peak <= len(ADDRESSES)
        assert max(held, default=0) <= c.widest <= SHARE


Table.TestCase.settings = settings(max_examples=400, stateful_step_count=50, deadline=None, derandomize=True)
TestTheTable = Table.TestCase
