"""(mint) `tvgw mint replay`: the stored record run through the minting table (design decision 85). It
reads the store and changes nothing.

With minted addresses the gateway could refuse every connection to an address no answer gave. Before a
packet is treated that way, the record can say what such a stage would have met. Each address an answer
gave the TV goes into a `mint.Minter` at the time of the answer, and each connection the TV began is put
in one class by what the table held then:

- `local`: to the gateway, to an address that is not public, or to port 53 (the gateway answers DNS
  wherever the TV aims it). Not judged;
- `ticket`: the table held one name's ticket for the address;
- `tickets`: it held several names' tickets. A minted address would say which name the connection meant;
  the record of real addresses cannot;
- `listed`: no ticket, and the profile lists the address and port as one the TV reaches without a lookup;
- `lapsed`: no ticket, and an older answer named the address;
- `never`: no ticket, and no answer the record holds named the address;
- `unassessed`: no ticket, and the record does not reach back a ticket's lifetime before the connection
  (an answer it never saw may explain it), or the connection's beginning was not seen.

`lapsed` and `never` are what a strict stage would refuse. The replay keeps one table for each of
LIFETIMES and judges every connection against each, so one pass shows what a shorter ticket would cost.
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
# seconds a connection is judged after it began: the answer it follows may be stamped that much later
SLACK = namebound.SLACK
PAST_TTL = 60.0  # seconds past its answer's own lifetime from which a connection was made from a cache
DNS_PORT = 53

LOCAL, TICKET, TICKETS, LISTED, LAPSED, NEVER, UNASSESSED = (
    "local",
    "ticket",
    "tickets",
    "listed",
    "lapsed",
    "never",
    "unassessed",
)
JUDGED = (TICKET, TICKETS, LISTED, LAPSED, NEVER, UNASSESSED)
REFUSED = (LAPSED, NEVER)  # what a strict stage would refuse
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


def _answers(conn: sqlite3.Connection, until: float) -> Iterator[tuple]:
    """(time, ANSWER, name, address, the answer's own lifetime) for each address an answer named up to
    `until`, oldest first."""
    for t, name, ip, ttl in conn.execute(
        """SELECT a.t, d.qname, a.ip, a.ttl FROM answer_ip a JOIN dns d ON d.id = a.dns_id
           WHERE a.t <= ? ORDER BY a.t""",
        (until,),
    ):
        yield t, ANSWER, name, ip, ttl


def _connections(conn: sqlite3.Connection, a: float, b: float) -> Iterator[tuple]:
    """(time judged, CONNECTION, began, protocol, address, port) for each connection that began in
    [a, b), oldest first. `began` is None for one whose beginning was not seen; it is placed by its end."""
    for t, start, proto, dst, dport in conn.execute(
        """SELECT COALESCE(t_start, t_end), t_start, proto, dst, dport FROM flows
           WHERE COALESCE(t_start, t_end) >= ? AND COALESCE(t_start, t_end) < ? ORDER BY 1""",
        (a, b),
    ):
        yield t + SLACK, CONNECTION, start, proto, dst, dport


def _class(names: tuple[str, ...], is_listed: bool, assessed: bool, answered: bool) -> str:
    """A judged connection's class, from the names with a live ticket for its address, whether the
    profile lists it, whether the record reaches back far enough, and whether any answer ever named it."""
    if names:
        return TICKET if len(names) == 1 else TICKETS
    if is_listed:
        return LISTED
    if not assessed:
        return UNASSESSED
    return LAPSED if answered else NEVER


def replay(
    conn: sqlite3.Connection,
    a: float,
    b: float,
    gw_ip: str,
    profile=None,
    lifetimes: tuple[float, ...] = LIFETIMES,
) -> dict | None:
    """What the minting table would have held for each connection that began in [a, b): for each
    lifetime the connections by class, the table's own counts and what a strict stage would have refused
    (by class, protocol and port, with how old the address's newest answer was). Counts only: no name
    and no address. None on a store whose answer record has not started."""
    since = namebound.coverage(conn)
    if since is None:
        return None
    exempt = listed(profile)
    tables = [mint.Minter(lifetime=lifetime) for lifetime in lifetimes]
    classes = [dict.fromkeys(JUDGED, 0) for _ in tables]
    refused: list[dict[tuple, list[float | None]]] = [{} for _ in tables]
    newest: dict[bytes, tuple[float, int | None]] = {}  # address -> its newest answer's time and lifetime
    answers = local = ttl_known = past_ttl = 0
    events = heapq.merge(_answers(conn, b + SLACK), _connections(conn, a, b), key=itemgetter(0, 1))
    for now, kind, *event in events:
        if kind == ANSWER:
            name, ip, ttl = event
            real = packed(ip)
            if real is None:
                continue
            answers += 1
            newest[real] = (now, ttl)
            for table in tables:
                table.mint(normalize(name), real, now)
            continue
        began, proto, dst, dport = event
        real = packed(dst)
        if real is None or dst == gw_ip or dport == DNS_PORT:
            local += 1
            continue
        answer = newest.get(real)
        age = None if answer is None or began is None else began - answer[0]
        if age is not None and answer[1] is not None:
            ttl_known += 1
            past_ttl += age > answer[1] + PAST_TTL
        for table, counts, cases in zip(tables, classes, refused, strict=True):
            # the table at a connection's end says nothing of its beginning: unseen, it has no ticket
            names = table.names_of(real, now) if began is not None else ()
            assessed = began is not None and began - table.lifetime >= since
            cls = _class(names, (dst, dport) in exempt, assessed, answer is not None)
            counts[cls] += 1
            if cls in REFUSED:
                cases.setdefault((cls, proto, dport), []).append(age)
    return {
        "window": [a, b],
        "since": since,
        "answers": answers,
        "local": local,
        "judged": sum(classes[0].values()),
        "pool": mint.capacity(mint.POOL),
        "ttl": {"known": ttl_known, "past": past_ttl},
        "lifetimes": [
            {
                "lifetime": table.lifetime,
                "connections": counts,
                "tickets": asdict(table.counts),
                "refused": [_case(*key, ages) for key, ages in sorted(cases.items(), key=_most_first)],
            }
            for table, counts, cases in zip(tables, classes, refused, strict=True)
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
