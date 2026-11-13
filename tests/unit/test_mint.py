"""(mint) The minting table of design decision 85, by example: one address for each (name, real address),
its lifetime and rest to the second, a name's share, and the counts. The same promises, over every order
of events hypothesis can find, are in test_mint_properties.py."""

import ipaddress

import pytest

from tvgw import dnsgate, mint, namebound

LIFE, REST = 100.0, 300.0
TINY = ipaddress.ip_network("198.18.0.252/30")  # .252 .253 .254 and .255, which is never given out
A, B, C, D = (bytes([203, 0, 113, last]) for last in (1, 2, 3, 4))


def table(**kw) -> mint.Minter:
    return mint.Minter(TINY, **{"lifetime": LIFE, "rest": REST, **kw})


def addresses(pool: ipaddress.IPv4Network) -> list[bytes]:
    return [a.packed for a in pool if mint.given_out(int(a))]


@pytest.mark.parametrize(
    "pool",
    [
        "198.18.0.0/15",
        "198.18.0.0/24",
        "198.18.0.252/30",
        "198.18.0.255/32",
        "198.18.1.0/32",
        "198.18.7.9/32",
    ],
)
def test_the_capacity_is_every_address_but_those_ending_in_0_and_255(pool):
    net = ipaddress.ip_network(pool)
    assert mint.capacity(net) == len(addresses(net))


@pytest.mark.parametrize("pool", ["198.18.0.252/30", "198.18.1.0/30", "198.18.0.8/31", "198.18.7.9/32"])
def test_the_pool_is_given_out_in_order_to_its_last_address_and_no_further(pool):
    net = ipaddress.ip_network(pool)
    m = mint.Minter(net, lifetime=LIFE, rest=REST)
    got = [m.mint(f"n{i}.example", A, 0.0)[0] for i in range(net.num_addresses + 1)]
    assert [t.minted for t in got if t] == addresses(net) and got[-1] is None
    assert (m.counts.minted, m.counts.refused, len(m)) == (
        len(addresses(net)),
        net.num_addresses + 1 - len(addresses(net)),
        len(addresses(net)),
    )


def test_the_defaults_are_the_benchmarking_range_the_gates_day_and_a_longer_rest():
    assert mint.capacity(mint.POOL) == 130_048 and mint.POOL.subnet_of(ipaddress.ip_network("198.18.0.0/15"))
    assert mint.LIFETIME == dnsgate.TTL == namebound.WINDOW
    assert mint.REST > mint.LIFETIME


def test_one_address_under_two_names_gets_two_minted_addresses_each_naming_its_own():
    m = table()
    (one, ops), (two, _) = m.mint("a.example", A, 0.0), m.mint("b.example", A, 0.0)
    assert [one.minted, two.minted] == addresses(TINY)[:2]
    assert ops == [mint.Op(mint.ADD, one.minted, A, LIFE)]
    assert m.names_of(A, 1.0) == ("a.example", "b.example") and m.names_of(B, 1.0) == ()
    assert m.lookup(two.minted, 1.0) is two and m.lookup(A, 1.0) is None


@pytest.mark.parametrize(("later", "alive"), [(LIFE - 1, True), (LIFE, False), (LIFE + 1, False)])
def test_a_ticket_lives_its_lifetime_from_the_last_answer_and_not_a_second_more(later, alive):
    m = table()
    first, _ = m.mint("a.example", A, 0.0)
    again, ops = m.mint("a.example", A, 50.0)  # answered again: the same address, a later end
    assert again is first and ops == [mint.Op(mint.ADD, first.minted, A, LIFE)]
    assert (m.counts.minted, m.counts.renewed) == (1, 1)
    at = 50.0 + later
    assert (m.lookup(first.minted, at) is first) == alive == bool(m.names_of(A, at))
    m.expire(at)
    assert len(m) == alive and m.counts.expired == (not alive)


def test_a_ticket_answered_again_does_not_hold_up_the_ones_that_ran_out_behind_it():
    m = table()
    m.mint("a.example", A, 0.0), m.mint("b.example", B, 1.0)
    m.mint("a.example", A, 40.0)  # a.example now outlives b.example, which was made after it
    m.expire(LIFE + 20.0)
    assert len(m) == 1 and m.names_of(A, LIFE + 20.0) == ("a.example",) and m.counts.expired == 1


@pytest.mark.parametrize(("rested", "given"), [(REST - 1, False), (REST, True)])
def test_a_used_address_goes_to_another_pair_only_after_its_rest_and_the_longest_rested_first(rested, given):
    """Three addresses, three pairs. The first ticket runs out at LIFE, the other two are revoked later:
    a fourth pair gets the first address once it has rested REST from the moment it ran out, and until
    then gets none. The table that refused is as it was."""
    m = table()
    first = m.mint("a.example", A, 0.0)[0].minted
    m.mint("b.example", B, 60.0), m.mint("b.example", C, 60.0)
    m.revoke("b.example", 150.0)
    ticket, ops = m.mint("c.example", D, LIFE + rested)
    assert (ticket.minted if ticket else None) == (first if given else None)
    assert (ops, len(m), m.counts.refused) == (
        ([mint.Op(mint.ADD, first, D, LIFE)], 1, 0) if given else ([], 0, 1)
    )
    assert m.counts.peak == 3  # the most at once, not the number now


def test_a_name_over_its_share_loses_its_own_least_recently_answered_ticket():
    m = mint.Minter(lifetime=LIFE, rest=REST, per_name=2)
    old, _ = m.mint("a.example", A, 0.0)
    kept, _ = m.mint("a.example", B, 1.0)
    other, _ = m.mint("b.example", A, 2.0)
    m.mint("a.example", A, 3.0)  # answered again: now B is the least recently answered
    new, ops = m.mint("a.example", C, 4.0)
    assert ops == [mint.Op(mint.DEL, kept.minted), mint.Op(mint.ADD, new.minted, C, LIFE)]
    assert (
        m.names_of(B, 4.0) == () and m.lookup(old.minted, 4.0) is old and m.lookup(other.minted, 4.0) is other
    )
    assert (m.counts.evicted, m.counts.widest, m.counts.peak, len(m)) == (1, 2, 3, 3)


def test_an_answer_refused_for_want_of_an_address_costs_its_name_no_ticket():
    m = mint.Minter(ipaddress.ip_network("198.18.0.8/31"), lifetime=LIFE, rest=REST, per_name=2)
    held = [m.mint("a.example", real, 0.0)[0] for real in (A, B)]
    assert m.mint("a.example", C, 1.0) == (None, [])
    assert [m.lookup(t.minted, 1.0) for t in held] == held and (m.counts.evicted, m.counts.refused) == (0, 1)


def test_revoking_a_name_ends_its_tickets_and_no_other_names():
    m = table()
    mine = [m.mint("a.example", real, 0.0)[0] for real in (A, B)]
    other, _ = m.mint("b.example", A, 0.0)
    gone, ops = m.revoke("a.example", 10.0)
    assert gone == mine and ops == [mint.Op(mint.DEL, t.minted) for t in mine]
    assert m.names_of(A, 10.0) == ("b.example",) and m.lookup(other.minted, 10.0) is other
    assert m.counts.revoked == 2 and m.revoke("a.example", 11.0) == ([], [])
    assert m.counts.widest == 2  # a.example's two, though the name answered last holds one


def test_the_clock_never_goes_back():
    """A caller's clock stepped back (NTP, a restart): the ticket is made at the table's own time, so no
    ticket ends before one made earlier and the resting addresses stay in order."""
    m = mint.Minter(ipaddress.ip_network("198.18.0.8/31"), lifetime=LIFE, rest=REST)
    m.mint("a.example", A, 100.0)
    late, _ = m.mint("b.example", B, 40.0)
    assert (late.born, late.expires, m.clock) == (100.0, 100.0 + LIFE, 100.0)
    m.revoke("b.example", 40.0)  # its address rests from 100, the table's time, not from 40
    assert m.mint("c.example", C, 100.0 + REST - 1)[0] is None
    assert m.mint("c.example", C, 100.0 + REST)[0].minted == late.minted
