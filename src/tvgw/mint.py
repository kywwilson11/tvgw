"""(mint) The minting table of design decision 85: one made-up address for each (name, real address)
the filter answers with. This module is the table alone. It opens no socket and reads no store.

Today the TV is told a server's real address, and one address can serve thousands of names: a connection
to it names nothing the gateway can check before the first packet is through. If the TV were told an
address that exists nowhere else, made for one name and one real address, the address the TV connects to
would itself say which name it means, and an address nobody answered would lead nowhere. The table is
what keeps those addresses. `Minter` takes the time as an argument and returns, with each change, the
changes the kernel's map needs (`Op`), so the whole of it runs in tests. What it promises:

- a pair that is alive has one ticket, and a minted address stands for one pair;
- a pair answered again while its ticket lives keeps its address, and lives LIFETIME from that answer;
- an address is given to another pair only after it has rested REST seconds: the TV may still hold it in
  a cache, and it must then meet a refusal, never another name's server. An address never given goes
  first, then the one that has rested longest. With none rested the answer gets no ticket (None), which
  is counted: a full pool costs a refusal, never a wrong address;
- a name over its share (PER_NAME) loses its own least recently answered ticket, and no other name's;
- the table's clock never goes back, whatever time it is handed.

The first user is `tvgw.mintreplay`, which runs the stored record through the table and changes nothing.
"""

from __future__ import annotations

import ipaddress
from collections import OrderedDict, deque
from dataclasses import dataclass

# RFC 2544's benchmarking range: addresses no internet host answers from and no home network uses
POOL = ipaddress.ip_network("198.18.0.0/15")
LIFETIME = 86_400.0  # seconds a ticket lives after the last answer that named its pair: the gate's day
# seconds an address rests after its ticket ended before another pair may get it. A week: the oldest
# answer the reference's TV was seen to connect by was five days old (2 connections in 9,079 over 14 days)
REST = 7 * 86_400.0
PER_NAME = 256  # live tickets one name may hold

ADD, DEL = "add", "del"


@dataclass(frozen=True)
class Op:
    """One change for the kernel's map: `add` (or renew) minted -> real for `timeout` seconds, or `del`.
    A ticket that runs out needs none: the kernel's element has the same timeout and goes by itself."""

    kind: str
    minted: bytes
    real: bytes = b""
    timeout: float = 0.0


@dataclass(slots=True)
class Ticket:
    """One pair's address: `minted` stands for `name` at `real` until `expires`."""

    minted: bytes
    name: str
    real: bytes
    born: float
    answered: float  # the last answer that named the pair
    expires: float


@dataclass
class Counts:
    minted: int = 0  # tickets made
    renewed: int = 0  # answers that named a live pair again
    expired: int = 0
    revoked: int = 0
    evicted: int = 0  # tickets ended because their name was over its share
    refused: int = 0  # answers that got no ticket: no address had rested
    peak: int = 0  # the most tickets alive at once
    widest: int = 0  # the most tickets one name held at once


def given_out(address: int) -> bool:
    """Whether the pool hands this address out: not one that ends in .0 or .255, which some network
    stacks take for a network or broadcast address whatever the mask."""
    return address & 0xFF not in (0, 255)


def capacity(pool: ipaddress.IPv4Network) -> int:
    """How many of the pool's addresses are given out."""
    first, last = int(pool.network_address), int(pool.broadcast_address)
    zeros = last // 256 - (first - 1) // 256  # the multiples of 256 in [first, last]
    ones = (last + 1) // 256 - first // 256  # and the addresses just below one
    return pool.num_addresses - zeros - ones


class Minter:
    """The table. Every method that asks or changes takes the time; none reads a clock."""

    def __init__(
        self,
        pool: ipaddress.IPv4Network = POOL,
        lifetime: float = LIFETIME,
        rest: float = REST,
        per_name: int = PER_NAME,
    ):
        self.pool = pool
        self.lifetime, self.rest, self.per_name = lifetime, rest, per_name
        self.clock = float("-inf")
        self.next_unused = int(
            pool.network_address
        )  # every address from here to the pool's end was never given
        self.resting: deque[tuple[float, bytes]] = deque()  # (ended, address), the longest rested first
        # four views of the same tickets. `by_pair` and each name's tickets run from the least recently
        # answered to the most: the first is the next to expire, and the one a name over its share loses
        self.by_pair: OrderedDict[tuple[str, bytes], Ticket] = OrderedDict()
        self.by_name: dict[str, OrderedDict[bytes, Ticket]] = {}
        self.by_minted: dict[bytes, Ticket] = {}
        self.by_real: dict[bytes, dict[str, Ticket]] = {}
        self.counts = Counts()

    def __len__(self) -> int:
        """The tickets alive at the table's clock."""
        return len(self.by_pair)

    # ---- asking ----------------------------------------------------------------------------------------
    def lookup(self, minted: bytes, now: float) -> Ticket | None:
        """The live ticket of a minted address: what a connection to it means."""
        ticket = self.by_minted.get(minted)
        return ticket if ticket is not None and ticket.expires > now else None

    def names_of(self, real: bytes, now: float) -> tuple[str, ...]:
        """The names with a live ticket for a real address. A shadow's question: it sees the connections
        the TV makes to real addresses, and asks what the table would have let through."""
        return tuple(name for name, ticket in self.by_real.get(real, {}).items() if ticket.expires > now)

    # ---- changing --------------------------------------------------------------------------------------
    def expire(self, now: float) -> None:
        """Move the clock on to `now` and end every ticket whose time has passed. An address rests from
        the moment its ticket ran out, which is when the kernel's element went, not from this call."""
        self.clock = max(self.clock, now)
        while self.by_pair:
            ticket = next(iter(self.by_pair.values()))
            if ticket.expires > self.clock:
                break
            self._end(ticket, ticket.expires)
            self.counts.expired += 1

    def mint(self, name: str, real: bytes, now: float) -> tuple[Ticket | None, list[Op]]:
        """An answer named (name, real): its ticket, made or renewed, and the kernel's changes. None when
        no address may be given; the table is then as it was."""
        self.expire(now)
        now = self.clock
        ops: list[Op] = []
        ticket = self.by_pair.get((name, real))
        if ticket is not None:
            ticket.answered, ticket.expires = now, now + self.lifetime
            self.by_pair.move_to_end((name, real))
            self.by_name[name].move_to_end(real)
            self.counts.renewed += 1
        else:
            minted = self._address(now)
            if minted is None:
                self.counts.refused += 1
                return None, ops
            held = self.by_name.get(name)
            if held is not None and len(held) >= self.per_name:
                oldest = next(iter(held.values()))
                self._end(oldest, now)
                ops.append(Op(DEL, oldest.minted))
                self.counts.evicted += 1
            ticket = Ticket(minted, name, real, born=now, answered=now, expires=now + self.lifetime)
            self.by_pair[name, real] = self.by_minted[minted] = ticket
            self.by_name.setdefault(name, OrderedDict())[real] = ticket
            self.by_real.setdefault(real, {})[name] = ticket
            self.counts.minted += 1
            self.counts.peak = max(self.counts.peak, len(self.by_pair))
            self.counts.widest = max(self.counts.widest, len(self.by_name[name]))
        ops.append(Op(ADD, ticket.minted, real, self.lifetime))
        return ticket, ops

    def revoke(self, name: str, now: float) -> tuple[list[Ticket], list[Op]]:
        """End every ticket of `name` now: the tickets, and the deletes that take them from the kernel."""
        self.expire(now)
        gone = list(self.by_name.get(name, {}).values())
        for ticket in gone:
            self._end(ticket, self.clock)
        self.counts.revoked += len(gone)
        return gone, [Op(DEL, ticket.minted) for ticket in gone]

    # ---- inside ----------------------------------------------------------------------------------------
    def _end(self, ticket: Ticket, ended: float) -> None:
        """Take a ticket out of every view and start its address's rest. Every caller has run `expire`
        first, so `ended` never comes before an earlier call's and `resting` stays in order."""
        del self.by_pair[ticket.name, ticket.real], self.by_minted[ticket.minted]
        for view, outer, inner in (
            (self.by_name, ticket.name, ticket.real),
            (self.by_real, ticket.real, ticket.name),
        ):
            del view[outer][inner]
            if not view[outer]:
                del view[outer]
        self.resting.append((ended, ticket.minted))

    def _address(self, now: float) -> bytes | None:
        """An address that may be given now: one never given, else the longest rested, once that is
        REST."""
        end = int(self.pool.broadcast_address)
        while self.next_unused <= end:
            address, self.next_unused = self.next_unused, self.next_unused + 1
            if given_out(address):
                return address.to_bytes(4, "big")
        if not self.resting or now - self.resting[0][0] < self.rest:
            return None
        return self.resting.popleft()[1]
