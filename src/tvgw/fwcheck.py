"""(fwcheck) The firewall, worked out for every packet the rules can tell apart (design decision 86).

`tvgw-apply` prints nftables rules. What they do is otherwise argued in comments and sampled by
probes. This module reads the scripts the apply hands to nft, follows a packet through them the way the
kernel would, and does so once for each class of packets the rules can tell apart. `tvgw.fwpolicy` holds
what must be true of every class; the two together are a test, and neither touches a kernel.

**What is read.** Exactly what the apply emits: tables in block form and as `add` commands, base chains
with their hook and priority, sets, and each rule clause by clause. A clause the reader does not know
stops it with the rule named: the model cannot fall behind the script without saying so.

**How a packet travels.** It arrives on an interface: the ingress chains of that device, then
prerouting, then input if its destination is one of the gateway's own addresses (after any `dnat`) and
forward then postrouting if not. Within a hook the base chains run in priority order. An `accept` ends
one base chain and the next one still runs; a `drop` or `reject` ends the packet. NAT chains see only a
connection's first packet. Packets the gateway itself sends (the output hook) are read and not followed.

**What the rules cannot decide** is left open and both ways are followed: whether a `limit` still has
room, whether an address is in a set a daemon fills, how many packets a connection has carried, a
packet handed to a `queue`. A rule with no verdict never splits the walk on such a question; what it
counts is then marked as possible, not sure.

**One packet per class, found by running.** A walk starts knowing nothing of the packet. The first time
a rule asks for a field nobody fixed (`Need`), the walk is run again once for each value of that field
that any rule could tell apart (`Ruleset.domain`). A walk that ends without asking stands for every
packet that shares what it did ask: fields it never read cannot have changed its end. So the classes are
the rules' own, none is sampled, and their number is the number of ways through the rules, not the size
of the header space.
"""

from __future__ import annotations

import copy
import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace

ACCEPT, DROP, REJECT = "accept", "drop", "reject"
REFUSALS = (DROP, REJECT)
INGRESS, PREROUTING, INPUT, FORWARD, POSTROUTING, OUTPUT = (
    "ingress",
    "prerouting",
    "input",
    "forward",
    "postrouting",
    "output",
)
# nftables' names for priorities, in the inet family
PRIORITIES = {"raw": -300, "mangle": -150, "dstnat": -100, "filter": 0, "security": 50, "srcnat": 100}
STATES = ("new", "established", "related", "invalid")
ROUTED = (FORWARD, POSTROUTING, OUTPUT)  # the hooks at which a packet has a way out
HOOKS = (INGRESS, PREROUTING, INPUT, FORWARD, POSTROUTING, OUTPUT)
FAMILIES = ("inet", "netdev")  # the tables the apply makes; another family sees other packets
OTHER_IF, OTHER_PROTO, OTHER_PORT = "other0", "gre", 40000  # what stands for a value nothing names


class Need(Exception):
    """A walk asked for something nobody has fixed: a packet's field, or a question the rules leave open."""

    def __init__(self, what):
        super().__init__(what)
        self.what = what


def prefix(text: str) -> tuple[int, int]:
    """An address or a prefix as (network, mask)."""
    net = ipaddress.ip_network(text.strip(), strict=False)
    return int(net.network_address), int(net.netmask)


def within(address: int, prefixes: Iterable[tuple[int, int]]) -> bool:
    return any(address & mask == base for base, mask in prefixes)


@dataclass(frozen=True)
class Rule:
    """One rule: its clauses in order, each a step that lets the walk go on or not, and its verdict."""

    chain: str
    text: str
    steps: tuple[Callable[[Walk], bool], ...]
    verdict: tuple | None  # (ACCEPT,), (DROP,), (REJECT, how), ("jump", chain), ("return",), ("dnat", ...)
    comment: str | None
    counted: bool


@dataclass
class Chain:
    table: tuple[str, str]  # (family, name)
    name: str
    rules: list[Rule] = field(default_factory=list)
    hook: str | None = None  # None for a chain that is only jumped to
    priority: int = 0
    nat: bool = False
    device: str | None = None
    policy: str = ACCEPT


@dataclass(frozen=True)
class Outcome:
    """Where one walk ended, and by which rules. `ticked` and `logged` are the comments of the counters
    and the prefixes of the logs it surely passed; `possible` the same for rules that may or may not have
    matched."""

    verdict: str
    by: Rule | None  # the rule that refused it
    hook: str  # where it was refused, or INPUT or FORWARD for one that passed
    met: tuple[Rule, ...]  # every rule that matched on the way, in order
    ticked: frozenset[str]
    logged: frozenset[str]
    possible: frozenset[str]
    daddr: int | None  # the destination after any dnat, when the walk read it
    dport: int | None


class Walk:
    """One packet's way through the rules: what is fixed of it, and what the rules it met did."""

    def __init__(self, fixed: Mapping, static: Mapping[str, list[tuple[int, int]]]):
        self.fixed, self.static = fixed, static  # `fixed` is replaced, never changed, when a dnat rewrites
        self.rule: Rule | None = None
        self.hook = INGRESS
        self.met: list[Rule] = []
        self.unsure = False  # the rule being read has asked something left open, and has no verdict
        self.ticked: set[str] = set()
        self.logged: set[str] = set()
        self.possible: set[str] = set()

    def get(self, name):
        try:
            return self.fixed[name]
        except KeyError:
            raise Need(name) from None

    def open(self, question: tuple, wanted: bool = True) -> bool:
        """Whether a question the rules leave open has the answer a clause wants. A rule with a verdict
        needs the answer; one without only counts and logs, so the walk goes on as if it had, and what
        the rule does is `possible`."""
        if question in self.fixed:
            return self.fixed[question] == wanted
        if self.rule is not None and self.rule.verdict is None:
            self.unsure = True
            return True
        raise Need(question)

    def note(self, into: set[str], what: str) -> None:
        (self.possible if self.unsure else into).add(what)

    def member(self, name: str, asked: str, address: int, wanted: bool) -> bool:
        """Whether an address is in a set, or out of it, as a clause wants: known for the sets the apply
        fills, open for a daemon's."""
        if name in self.static:
            return within(address, self.static[name]) == wanted
        return self.open(("in", name, asked), wanted)


# ---- the clauses -----------------------------------------------------------------------------------------
def _list(body: str) -> tuple[str, ...]:
    return tuple(x.strip().strip('"') for x in body.split(","))


def _interface(m: re.Match) -> Callable[[Walk], bool]:
    key, wanted, negated = m[1][:3], _list(m[3] if m[3] is not None else m[4]), bool(m[2])
    if any("*" in name for name in wanted):
        raise ValueError("a name with * is every name that begins so")
    if key == "oif":  # before a packet is routed it has no way out, and the kernel reads an empty name
        return lambda w: ((w.get(key) if w.hook in ROUTED else "") in wanted) != negated
    return lambda w: (w.get(key) in wanted) != negated


def _address(m: re.Match) -> Callable[[Walk], bool]:
    key, negated, what = m[1], bool(m[2]), m[3]
    if what.startswith("@"):
        return lambda w: w.get("family") == 4 and w.member(what[1:], key, w.get(key), not negated)
    prefixes = [prefix(x) for x in _list(what.strip("{} "))]
    return lambda w: w.get("family") == 4 and within(w.get(key), prefixes) != negated


def _l4proto(m: re.Match) -> Callable[[Walk], bool]:
    wanted, negated = _list(m[2] if m[2] is not None else m[3]), bool(m[1])
    if any(name.isdigit() for name in wanted):
        raise ValueError("a protocol by number is one this model knows by name")
    return lambda w: (w.get("proto") in wanted) != negated


def _port(m: re.Match) -> Callable[[Walk], bool]:
    """`tcp dport` and `udp dport` are of that protocol alone. `th dport` is two bytes of whatever follows
    the IP header: a port for TCP and UDP, and for any other protocol bytes this model does not hold, so
    the match is open."""
    of, key, negated = m[1], m[2], bool(m[3])
    if m[6] is not None:  # a set a daemon fills
        question = ("in", m[6], key)
        return lambda w: (of == "th" or w.get("proto") == of) and w.open(question, not negated)
    wanted = {int(x) for x in _list(m[4] if m[4] is not None else m[5])}
    if of != "th":
        return lambda w: w.get("proto") == of and (w.get(key) in wanted) != negated
    raw = ("th", m[0])
    return lambda w: (w.get(key) in wanted) != negated if w.get("proto") in ("tcp", "udp") else w.open(raw)


def _state(m: re.Match) -> Callable[[Walk], bool]:
    wanted = m[1].split(",")
    if not set(wanted) <= set(STATES):
        raise ValueError(
            f"a connection state this model does not follow: {sorted(set(wanted) - set(STATES))}"
        )
    return lambda w: w.get("ct") in wanted


def _open(kind: str, proto: str | None = None) -> Callable[[re.Match], Callable[[Walk], bool]]:
    """A clause the packet's fields do not settle: open, and the same question wherever its text recurs."""
    return lambda m: lambda w: (proto is None or w.get("proto") == proto) and w.open((kind, m[0]))


def _counter(w: Walk) -> bool:
    if w.rule.comment:
        w.note(w.ticked, w.rule.comment)
    return True


def _log(m: re.Match) -> Callable[[Walk], bool]:
    what = m[1] if m[1] is not None else f"group {m[2]}"
    return lambda w: w.note(w.logged, what) or True


def _limit(w: Walk) -> bool:
    """Over its rate a rule does not match. With a verdict that is a question; without one the walk goes
    on, and what the rule does after its limit is possible, not sure."""
    if w.rule.verdict is not None:
        return w.open(("limit", w.rule.chain, w.rule.text))
    w.unsure = True
    return True


_SET = r"@(\w+)"
_CONCAT = r"(?:ip saddr|ip daddr|meta l4proto|th sport|th dport)"
MATCHES: tuple[tuple[str, Callable[[re.Match], Callable[[Walk], bool]]], ...] = (
    (r'(iifname|oifname) (!= )?(?:"([^"]+)"|\{ ([^}]*) \})', _interface),
    (
        rf"{_CONCAT}(?: \. {_CONCAT})+ (?:!= )?{_SET}",
        lambda m: (
            lambda w: w.open(("in", m[1], m[0].partition(" @")[0].removesuffix(" !=")), " != " not in m[0])
        ),
    ),
    (rf"ip (saddr|daddr) (!= )?({_SET[:1]}\w+|\{{ [^}}]* \}}|\d[\d./]*)", _address),
    (r"ct state ([a-z,]+)", _state),
    (r"ct original packets \S+ \d+", _open("carried")),
    (r"meta nfproto ipv([46])", lambda m: lambda w: w.get("family") == int(m[1])),
    (r"meta l4proto (!= )?(?:\{ ([^}]*) \}|(\w+))", _l4proto),
    (rf"(tcp|udp|th) (sport|dport) (!= )?(?:\{{ ([^}}]*) \}}|(\d+)|{_SET})", _port),
    (
        r"icmp type echo-request",
        lambda m: lambda w: w.get("family") == 4 and w.get("proto") == "icmp" and w.get("echo"),
    ),
    (r"ip length <= (\d+)", lambda m: lambda w: w.get("family") == 4 and w.get("length") <= int(m[1])),
    (r"tcp flags syn\b", _open("flags", "tcp")),
    (r"tcp flags & \(syn \| rst\) == 0", _open("flags", "tcp")),
    (r"ether type ip6", lambda m: lambda w: w.get("family") == 6),
    (r"meta skuid != 0", _open("sender")),
    (r"limit rate \d+/\w+", lambda m: _limit),
    (r"counter\b", lambda m: _counter),
    (r'log (?:prefix "([^"]*)"|group (\d+)(?: snaplen \d+)?(?: queue-threshold \d+)?)', _log),
    # what changes a packet or a set and decides nothing
    (r"meta mark set \S+|tcp option maxseg size set rt mtu|(?:add|update) @\w+ \{ [^{}]* \}", lambda m: None),
)
VERDICTS: tuple[tuple[str, Callable[[re.Match], tuple]], ...] = (
    (r"accept\b", lambda m: (ACCEPT,)),
    (r"drop\b", lambda m: (DROP,)),
    (r"reject(?: with (tcp reset|icmpx admin-prohibited))?", lambda m: (REJECT, m[1] or "")),
    (r"jump (\w+)", lambda m: ("jump", m[1])),
    (r"return\b", lambda m: ("return",)),
    (r"dnat ip to ([\d.]+):(\d+)", lambda m: ("dnat", prefix(m[1])[0], int(m[2]))),
    (r"masquerade\b", lambda m: (ACCEPT,)),
    (r"queue flags bypass to \d+", lambda m: ("queue",)),
)
COMMENT = re.compile(r'comment "([^"]*)"')


def rule(chain: str, text: str) -> Rule:
    """One rule, read clause by clause from the left, as nft runs it. Only a comment may follow a verdict."""
    comment = COMMENT.search(text)
    steps: list[Callable[[Walk], bool]] = []
    verdict, counted, rest = None, False, COMMENT.sub("", text).strip()
    while rest:
        for pattern, build in (*MATCHES, *VERDICTS) if verdict is None else ():
            m = re.match(pattern, rest)
            if m is None:
                continue
            try:
                built = build(m)
            except ValueError as why:
                raise ValueError(f"fwcheck: {why}: {m[0]!r} in the rule {text!r}") from None
            if (pattern, build) in VERDICTS:
                verdict = built
            elif (step := built) is not None:
                steps.append(step)
                counted = counted or step is _counter
            rest = rest[m.end() :].strip()
            break
        else:
            raise ValueError(f"fwcheck: a clause this model does not know: {rest!r} in the rule {text!r}")
    return Rule(chain, text, tuple(steps), verdict, comment[1] if comment else None, counted)


# ---- the scripts -----------------------------------------------------------------------------------------
_BASE = re.compile(r'type (\w+) hook (\w+)(?: device "([^"]+)")? priority ([^;]+); policy (\w+);')
_ELEMENTS = re.compile(r"\{ ([^{}]*) \}")


def priority(text: str) -> int:
    """`filter - 10`, `mangle + 10`, `-500`."""
    name, sign, number = re.fullmatch(r"([a-z]+)?\s*(?:([+-])\s*)?(\d+)?", text.strip()).groups()
    return PRIORITIES.get(name, 0) + (-1 if sign == "-" else 1) * int(number or 0)


class Ruleset:
    """Every table the scripts leave behind, and the walks through them. `local` is the gateway's own
    addresses: a packet for one of them is delivered (input), any other is forwarded."""

    def __init__(self, scripts: Iterable[str], local: Iterable[str] = ()):
        self.chains: dict[tuple[tuple[str, str], str], Chain] = {}
        self.static: dict[str, list[tuple[int, int]]] = {}  # the sets the apply fills, by name
        self.local = [prefix(x) for x in local]
        self._found: dict[str, set] | None = None  # constants(), once the scripts are read
        self._bases: dict[str, list[Chain]] = {}  # bases(), by hook, once asked
        for script in scripts:
            self._read(script)

    # ---- reading ---------------------------------------------------------------------------------------
    def _read(self, script: str) -> None:
        table: tuple[str, str] | None = None  # the block being read, and inside it a chain or a set
        chain: Chain | None = None
        inset: tuple[str, list[str]] | None = None
        for raw in script.splitlines():
            line = " ".join(raw.split())
            if not line or line.startswith("#"):
                continue
            if inset is not None:  # a set over several lines: read whole, once it closes
                if line == "}":
                    self._set(inset[0], " ".join(inset[1]))
                    inset = None
                else:
                    inset[1].append(line)
            elif chain is not None:
                if line == "}":
                    chain = None
                elif base := _BASE.fullmatch(line):
                    self._base(chain, base)
                else:
                    chain.rules.append(rule(chain.name, line))
            elif table is not None:
                if line == "}":
                    table = None
                elif m := re.fullmatch(r"chain (\w+) \{", line):
                    if (table, m[1]) in self.chains:  # nft would add to it; the apply never does
                        raise ValueError(f"fwcheck: a chain this model has already read: {line!r}")
                    chain = self.chains[table, m[1]] = Chain(table, m[1])
                elif m := re.fullmatch(r"set (\w+) \{(.*)", line):
                    if m[2].rstrip().endswith("}"):
                        self._set(m[1], m[2])
                    else:
                        inset = (m[1], [m[2]])
                else:
                    raise ValueError(
                        f"fwcheck: a line this model does not know in table {table[1]}: {line!r}"
                    )
            elif m := re.fullmatch(r"table (\w+) (\w+) \{", line):
                table = self._table(m[1], m[2])
            elif m := re.fullmatch(r"delete table (\w+) (\w+)", line):
                self.chains = {key: c for key, c in self.chains.items() if key[0] != (m[1], m[2])}
            elif m := re.fullmatch(r"(?:add )?table (\w+) (\w+)", line):
                self._table(m[1], m[2])  # made so that a delete finds it
            elif m := re.fullmatch(r"add set (\w+) (\w+) (\w+) \{(.*)\}", line):
                self._table(m[1], m[2])
                self._set(m[3], m[4])
            elif m := re.fullmatch(r"add element \w+ \w+ (\w+) \{ (.*) \}", line):
                if m[1] not in self.static:
                    raise ValueError(f"fwcheck: elements for a set this model takes for a daemon's: {line!r}")
                self.static[m[1]] += [prefix(x) for x in _list(m[2])]
            elif m := re.fullmatch(r"add chain (\w+) (\w+) (\w+)(?: \{ (.*) \})?", line):
                made = self.chains.setdefault((self._table(m[1], m[2]), m[3]), Chain((m[1], m[2]), m[3]))
                if m[4]:
                    self._base(made, _BASE.fullmatch(m[4]))
            elif m := re.fullmatch(r"flush chain (\w+) (\w+) (\w+)", line):
                self.chains[(m[1], m[2]), m[3]].rules.clear()
            elif m := re.fullmatch(r"(add|insert) rule (\w+) (\w+) (\w+) (.*)", line):
                rules = self.chains[(m[2], m[3]), m[4]].rules
                rules.insert(len(rules) if m[1] == "add" else 0, rule(m[4], m[5]))
            else:
                raise ValueError(f"fwcheck: a line this model does not know: {line!r}")

    @staticmethod
    def _table(family: str, name: str) -> tuple[str, str]:
        if family not in FAMILIES:  # an ip6 or bridge table's rules are not for the packets followed here
            raise ValueError(f"fwcheck: a table of a family this model does not follow: {family} {name}")
        return family, name

    @staticmethod
    def _base(chain: Chain, m: re.Match | None) -> None:
        if m is None or m[2] not in HOOKS:
            raise ValueError(
                f"fwcheck: a base chain this model does not walk: {chain.name} in {chain.table[1]}"
            )
        chain.nat, chain.hook, chain.device = m[1] == "nat", m[2], m[3]
        chain.priority, chain.policy = priority(m[4]), m[5]

    def _set(self, name: str, declaration: str) -> None:
        """A set with `flags interval` and no timeout is one the apply fills, and its elements are
        known. Any other is filled while the gateway runs: what it holds is open."""
        flags = re.search(r"flags ((?:\w+(?:, )?)+)", declaration)
        named = set(_list(flags[1])) if flags else set()
        if "interval" in named and not named & {"timeout", "dynamic"}:
            elements = [
                x for body in _ELEMENTS.findall(declaration.partition("elements")[2]) for x in _list(body)
            ]
            self.static.setdefault(name, []).extend(prefix(x) for x in elements)

    def without(self, gone: Rule) -> Ruleset:
        """The same rules less one: how a test asks whether anything would notice that rule missing."""
        other = copy.copy(self)
        other.chains = {
            key: replace(chain, rules=[r for r in chain.rules if r is not gone])
            for key, chain in self.chains.items()
        }
        other._bases = {}
        return other

    # ---- walking ---------------------------------------------------------------------------------------
    def bases(self, hook: str) -> list[Chain]:
        """The base chains of one hook, in the order the kernel runs them."""
        if hook not in self._bases:
            of_hook = (c for c in self.chains.values() if c.hook == hook)
            self._bases[hook] = sorted(of_hook, key=lambda c: c.priority)
        return self._bases[hook]

    def _chain(self, chain: Chain, walk: Walk) -> tuple | None:
        """The verdict the chain's rules give the walk's packet; None when it leaves them without one."""
        for r in chain.rules:
            walk.rule, walk.unsure = r, False
            for step in r.steps:
                if not step(walk):
                    break
            else:
                walk.met.append(r)
                if r.verdict is None:
                    continue
                kind = r.verdict[0]
                if kind == "jump":
                    inner = self._chain(self.chains[chain.table, r.verdict[1]], walk)
                    if inner is not None:
                        return inner
                elif kind == "return":
                    return None
                elif kind == "dnat":
                    walk.fixed = {**walk.fixed, "daddr": r.verdict[1], "dport": r.verdict[2]}
                    return (ACCEPT, r)
                elif kind == "queue":  # whoever reads the queue decides; with nobody there it passes
                    return (ACCEPT if walk.open(("queue", r.text)) else DROP, r)
                else:
                    return (kind, r)
        return None

    def _through(self, hook: str, walk: Walk) -> tuple | None:
        """The refusal one hook's base chains give the walk's packet, in their order; None when it passes."""
        walk.hook = hook
        for chain in self.bases(hook):
            if chain.device is not None and chain.device != walk.get("iif"):
                continue
            if chain.nat and walk.get("ct") != "new":
                continue
            verdict = self._chain(chain, walk)
            if verdict is None and chain.policy != ACCEPT:
                verdict = (chain.policy, None)
            if verdict is not None and verdict[0] in REFUSALS:
                return verdict
        return None

    def walk(self, fixed: Mapping) -> Outcome:
        """One packet through every hook it meets. Raises Need for the first thing it must know."""
        walk = Walk(fixed, self.static)
        refusal, hook = None, INGRESS
        for hook in (INGRESS, PREROUTING):
            if (refusal := self._through(hook, walk)) is not None:
                break
        else:
            if walk.get("family") == 4:
                delivered = within(walk.get("daddr"), self.local)
            else:
                delivered = walk.get("delivered6")  # an IPv6 packet's route is not this model's to work out
            for hook in (INPUT,) if delivered else (FORWARD, POSTROUTING):
                if (refusal := self._through(hook, walk)) is not None:
                    break
            else:
                hook = INPUT if delivered else FORWARD
        ticked, logged = frozenset(walk.ticked), frozenset(walk.logged)
        return Outcome(
            refusal[0] if refusal else ACCEPT,
            refusal[1] if refusal else None,
            hook,
            tuple(walk.met),
            ticked,
            logged,
            frozenset(walk.possible) - ticked - logged,
            walk.fixed.get("daddr"),
            walk.fixed.get("dport"),
        )

    # ---- every class -----------------------------------------------------------------------------------
    def constants(self) -> dict[str, set]:
        """Every value a rule names, by the kind of field it is compared with."""
        found: dict[str, set] = {kind: set() for kind in ("if", "net", "sport", "dport", "proto", "length")}
        for chain in self.chains.values():
            found["if"] |= {chain.device} if chain.device else set()
            for r in chain.rules:
                text = COMMENT.sub("", r.text)
                for names in re.findall(r'[io]ifname (?:!= )?(?:"([^"]+)"|\{ ([^}]*) \})', text):
                    found["if"] |= set(_list(names[0] or names[1]))
                for what in re.findall(r"ip [sd]addr (?:!= )?(\{ [^}]* \}|\d[\d./]*)", text):
                    found["net"] |= {prefix(x) for x in _list(what.strip("{} "))}
                for key, what in re.findall(r"(?:tcp|udp|th) ([sd]port) (?:!= )?(\{ [^}]* \}|\d+)", text):
                    found[key] |= {int(x) for x in _list(what.strip("{} "))}
                for what in re.findall(r"meta l4proto (?:!= )?(\{ [^}]* \}|\w+)", text):
                    found["proto"] |= set(_list(what.strip("{} ")))
                found["net"] |= {prefix(to) for to in re.findall(r"dnat ip to ([\d.]+)", text)}
                found["dport"] |= {int(p) for p in re.findall(r"dnat ip to [\d.]+:(\d+)", text)}
                found["length"] |= {int(n) for n in re.findall(r"ip length <= (\d+)", text)}
        found["net"] |= {p for elements in self.static.values() for p in elements} | set(self.local)
        return found

    def classes(self, fixed: Mapping | None = None) -> Iterator[tuple[dict, Outcome]]:
        """Every class of packets the rules tell apart, with where it ends: (what the walk read, outcome).
        `fixed` narrows it to the packets that share those fields."""
        if self._found is None:
            self._found = self.constants()
        return ((known, ends[0]) for known, ends in explore([self.walk], self._found, fixed))


def unnamed(named: set, like):
    """A value nothing names: it stands for every value the rules, and the promises, do not tell apart.
    `like` is taken when it is free, and moved on until it is."""
    while like in named:
        like = like + 1 if isinstance(like, int) else like + "+"
    return like


def domain(what, found: Mapping[str, set]) -> tuple:
    """The values of one field that something could tell apart, given every value named (`constants`, and
    `fwpolicy.named`), with one more that nothing names; or the two answers to an open question."""
    if isinstance(what, tuple):
        return (True, False)
    if what in ("saddr", "daddr"):
        return tuple(atoms(found["net"]))
    if what in ("iif", "oif"):
        return (*sorted(found["if"]), unnamed(found["if"], OTHER_IF))
    if what in ("sport", "dport"):
        return (*sorted(found[what]), unnamed(found[what], OTHER_PORT))
    if what == "proto":
        named = found["proto"] | {"tcp", "udp", "icmp"}
        return (*sorted(named), unnamed(named, OTHER_PROTO))
    if what == "length":
        return tuple(sorted({n + more for n in found["length"] | {60} for more in (0, 1)}))
    return {"family": (4, 6), "ct": STATES, "echo": (True, False), "delivered6": (False, True)}[what]


def explore(
    walks: Sequence[Callable[[Mapping], Outcome]], found: Mapping[str, set], fixed: Mapping | None = None
) -> Iterator[tuple[dict, tuple[Outcome, ...]]]:
    """Every class of packets that any of `walks` tells apart, with where each of them ends it. One walk
    is one ruleset's classes; two are the classes on which two rulesets, or two views of one, can be
    compared. `found` is every value their rules name (`Ruleset.constants`, merged for several)."""
    domains: dict = {}
    todo = [dict(fixed or {})]
    while todo:
        known = todo.pop()
        try:
            yield known, tuple(walk(known) for walk in walks)
        except Need as need:
            if need.what not in domains:
                domains[need.what] = domain(need.what, found)
            todo += [{**known, need.what: value} for value in reversed(domains[need.what])]


def merged(*found: Mapping[str, set]) -> dict[str, set]:
    """The values several rulesets name, together."""
    return {kind: set().union(*(f[kind] for f in found)) for kind in found[0]}


def atoms(prefixes: Iterable[tuple[int, int]]) -> list[int]:
    """One address from each region the prefixes cut the address space into. Prefixes nest or are apart,
    so a region begins where a prefix begins or just after one ends."""
    prefixes = sorted(set(prefixes))
    starts = (
        {0} | {base for base, _ in prefixes} | {(base | (~mask & 0xFFFFFFFF)) + 1 for base, mask in prefixes}
    )
    seen: dict[frozenset, int] = {}
    for address in sorted(a for a in starts if a <= 0xFFFFFFFF):
        seen.setdefault(frozenset(p for p in prefixes if address & p[1] == p[0]), address)
    return sorted(seen.values())
