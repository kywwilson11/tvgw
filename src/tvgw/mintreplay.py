"""(mint) `tvgw mint replay`: the stored record run through the minting table (design decision 85). It
reads the store and changes nothing.

With minted addresses the gateway could refuse every connection to an address no answer gave. Before a
packet is treated that way, the record can say what such a stage would have met. Each address an answer
gave the TV goes into a `mint.Minter` at the time of the answer, and each connection the TV began is put
in one class by what the table held then:

- `local`: to an address that is not a public IPv4 address (the gateway's and the home network's are
  not: the TV's side must be numbered from a private range), or to port 53 (the gateway answers DNS
  wherever the TV aims it). Not judged;
- `ticket`: the table held one name's ticket for the address;
- `tickets`: it held several names' tickets. A minted address would say which name the connection meant;
  the record of real addresses cannot;
- `listed`: no ticket, and the profile lists the address and port as one the TV reaches without a lookup;
- `crowded`: no ticket, though an answer named the address within a ticket's lifetime: the pool was
  full, or the name was over its share;
- `lapsed`: no ticket, and the newest answer that named the address is older than a ticket's lifetime;
- `never`: no ticket, and no answer the record holds named the address;
- `unassessed`: no ticket, and the record does not reach back a ticket's lifetime before the connection
  (an answer it never saw may explain it), or the connection's beginning was not seen.

`crowded`, `lapsed` and `never` are what a strict stage would refuse. The replay keeps one table for
each of LIFETIMES and judges every connection against each, so one pass shows what a shorter ticket
would cost. Every table is given every answer the record holds up to the window's end, whatever the
window's start: what a table holds, and whether an address was ever answered, depend on all that came
before.

Two clocks meet here. An answer is stamped when its question arrived, and a connection's beginning is
conntrack's, so an answer's stamp may come up to SLACK after the connection it made possible. Each table
is therefore given every answer SLACK early and tickets that live SLACK longer: a ticket then covers a
connection from SLACK before its answer's stamp until one lifetime after it, and not a second less.
"""

from __future__ import annotations

import heapq
import socket
import sqlite3
from collections.abc import Iterator
from dataclasses import asdict
from operator import itemgetter

from tvgw import mint, namebound
from tvgw.names import is_public_address, normalize

# seconds a ticket lives, one table each; the last is the table's own, which the command's summary is of
LIFETIMES = (60.0, 3600.0, 6 * 3600.0, mint.LIFETIME)
SLACK = namebound.SLACK  # seconds an answer's stamp may trail the connection that followed the answer
# seconds after an answer's own lifetime beyond which a connection is counted as made from the TV's cache
PAST_TTL = 60.0
DNS_PORT = 53

LOCAL, TICKET, TICKETS, LISTED, CROWDED, LAPSED, NEVER, UNASSESSED = (
    "local",
    "ticket",
    "tickets",
    "listed",
    "crowded",
    "lapsed",
    "never",
    "unassessed",
)
JUDGED = (TICKET, TICKETS, LISTED, CROWDED, LAPSED, NEVER, UNASSESSED)
# what a strict stage would refuse (not `unassessed`: the record cannot say)
REFUSED = (CROWDED, LAPSED, NEVER)
ANSWER, CONNECTION = 0, 1  # the two kinds of event; at one moment the answer comes first


def packed(ip: str | None) -> bytes | None:
    """A public IPv4 address as its four bytes; None for anything else."""
    return socket.inet_aton(ip) if ip and is_public_address(ip) else None


def listed(profile) -> frozenset[tuple[str, int]]:
    """The (address, port) pairs a profile says the TV reaches without a lookup: the `address:port` each
    `hardcoded` entry of its generations begins with. An entry that begins with anything else lists
    nothing."""
    out = set()
    for generation in getattr(profile, "generations", ()):
        for entry in generation.hardcoded:
            address, _, port = entry.partition(" ")[0].rpartition(":")
            if port.isdigit() and is_public_address(address):
                out.add((address, int(port)))
    return frozenset(out)


def judged_address(dst: str | None, dport: int | None) -> bytes | None:
    """The four bytes of a connection's address when the connection is judged; None for a `local` one."""
    return None if dport == DNS_PORT else packed(dst)


def _answers(conn: sqlite3.Connection, until: float) -> Iterator[tuple]:
    """(the table's time, ANSWER, stamp, name, address, the answer's own lifetime) for each address an
    answer named before `until`, oldest first. The table's time is SLACK before the stamp."""
    for t, name, ip, ttl in conn.execute(
        """SELECT a.t, d.qname, a.ip, a.ttl FROM answer_ip a JOIN dns d ON d.id = a.dns_id
           WHERE a.t < ? ORDER BY a.t""",
        (until,),
    ):
        yield t - SLACK, ANSWER, t, name, ip, ttl


def _connections(conn: sqlite3.Connection, a: float, b: float) -> Iterator[tuple]:
    """(began, CONNECTION, protocol, address, port) for each connection that began in [a, b), oldest
    first, read by the index of beginnings."""
    for start, proto, dst, dport in conn.execute(
        "SELECT t_start, proto, dst, dport FROM flows WHERE t_start >= ? AND t_start < ? ORDER BY t_start",
        (a, b),
    ):
        yield start, CONNECTION, proto, dst, dport


def _unseen(conn: sqlite3.Connection, a: float, b: float) -> Iterator[tuple]:
    """(address, port) for each connection whose beginning was not seen and which ended in [a, b)."""
    return conn.execute(
        "SELECT dst, dport FROM flows WHERE t_start IS NULL AND t_end >= ? AND t_end < ?", (a, b)
    )


def _class(
    names: tuple[str, ...], is_listed: bool, assessed: bool, age: float | None, lifetime: float
) -> str:
    """A judged connection's class, from the names with a live ticket for its address, whether the
    profile lists it, whether the record reaches back a lifetime, and the age of the newest answer that
    named the address (None when none did)."""
    if names:
        return TICKET if len(names) == 1 else TICKETS
    if is_listed:
        return LISTED
    if age is not None and age < lifetime:
        return CROWDED  # an answer that should still hold a ticket, and none is held
    if not assessed:
        return UNASSESSED
    return NEVER if age is None else LAPSED


def replay(
    conn: sqlite3.Connection,
    a: float,
    b: float,
    profile=None,
    lifetimes: tuple[float, ...] = LIFETIMES,
) -> dict | None:
    """What the minting table would have held for each connection of [a, b): for each lifetime the
    connections by class, the table's own counts over every answer up to b, and what a strict stage
    would have refused (by class, protocol and port, with how old the address's newest answer was).
    `answers` counts the addresses the answers gave, an address answered again counted again. Counts
    only: no name and no address. None on a store whose answer record has not started."""
    since = namebound.coverage(conn)
    if since is None:
        return None
    exempt = listed(profile)
    tables = [mint.Minter(mint.POOL, lifetime=lifetime + SLACK) for lifetime in lifetimes]
    classes = [dict.fromkeys(JUDGED, 0) for _ in lifetimes]
    refused: list[dict[tuple, list[float | None]]] = [{} for _ in lifetimes]
    newest: dict[bytes, tuple[float, int | None]] = {}  # address -> its newest answer's stamp and lifetime
    answers = local = ttl_known = past_ttl = 0
    events = heapq.merge(_answers(conn, b + SLACK), _connections(conn, a, b), key=itemgetter(0, 1))
    for at, kind, *event in events:  # `at` is the table's time
        if kind == ANSWER:
            stamp, name, ip, ttl = event
            real = packed(ip)
            if real is None:
                continue
            answers += 1
            newest[real] = (stamp, ttl)
            for table in tables:
                table.mint(normalize(name), real, at)
            continue
        proto, dst, dport = event
        real = judged_address(dst, dport)
        if real is None:
            local += 1
            continue
        stamp, ttl = newest.get(real, (None, None))
        age = None if stamp is None else at - stamp
        if ttl is not None:
            ttl_known += 1
            past_ttl += age > ttl + PAST_TTL
        for lifetime, table, counts, cases in zip(lifetimes, tables, classes, refused, strict=True):
            cls = _class(
                table.names_of(real, at), (dst, dport) in exempt, at - lifetime >= since, age, lifetime
            )
            counts[cls] += 1
            if cls in REFUSED:
                cases.setdefault((cls, proto, dport), []).append(age)
    # a connection whose beginning was not seen: the table at its end says nothing of its beginning
    for dst, dport in _unseen(conn, a, b):
        if judged_address(dst, dport) is None:
            local += 1
            continue
        for counts in classes:
            counts[LISTED if (dst, dport) in exempt else UNASSESSED] += 1
    return {
        "window": [a, b],
        "since": since,
        "answers": answers,
        "local": local,
        "judged": sum(classes[0].values()),
        "pool": mint.capacity(tables[0].pool),
        "ttl": {"known": ttl_known, "past": past_ttl},
        "lifetimes": [
            {
                "lifetime": lifetime,
                "connections": counts,
                "tickets": asdict(table.counts),
                "refused": [_case(*key, ages) for key, ages in sorted(cases.items(), key=_most_first)],
            }
            for lifetime, table, counts, cases in zip(lifetimes, tables, classes, refused, strict=True)
        ],
    }


def _most_first(item: tuple) -> tuple:
    (cls, proto, dport), ages = item
    return -len(ages), cls, proto or "", dport or 0


def _case(cls: str, proto: str | None, dport: int | None, ages: list[float | None]) -> dict:
    """One line of what strict would refuse; `newest` and `oldest` are the ages, in seconds, of the
    newest answer that named each connection's address (None for `never`)."""
    known = [age for age in ages if age is not None]
    return {
        "class": cls,
        "proto": proto,
        "dport": dport,
        "n": len(ages),
        "newest": min(known, default=None),
        "oldest": max(known, default=None),
    }
