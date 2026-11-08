"""(ports) What the firewall itself refused the TV in the last minutes, for `tvgw refused` (decision 71).

`tvgw refused` read AdGuard Home's query log alone, so every refusal the kernel makes was invisible to it:
QUIC, encrypted lookups around the filter, the address blocks, the home network, LG's advertising ports,
an unusual port under STRICT_PORTS=yes, the clock port once it is narrowed, and the address gate if it ever
refuses. Before any of those walls refuses on probation, the report that answers "why did an app stop?"
has to see them. This reads two things the gateway already keeps, and writes nothing:

- **The counters.** Every refusing rule of `inet tvgw` (and the clock port's resolved chain in `inet
  tvgw_gate`) carries a counter and a comment. The count in the window is the live counter now, less the
  newest snapshot `tvgw verify --record` stored at or before the window's start (it takes one every ten
  minutes), stepped through the snapshots and the apply's own listings either side of a reload in
  between, as `queries.fw_activity` steps them: a lower count is a reload, whose whole count is new. So
  a count may reach back to that snapshot, up to ten minutes before the window, and the line says from
  when it counts. With no snapshot in the hour before (no store, a stopped timer), it counts from the
  last apply's listing, and says so.
- **The samples.** The rules whose refusals name a destination log a sample, at most six a minute (`tvgw-
  oddport`, `tvgw-ntp`, `tvgw-adport`, and `tvgw-gate` once the gate refuses): the kernel journal holds
  them at once, while the store has them only after the hourly ingest. They give an unusual port's or a
  clock server's address, named from the TV's own answers in the store and from the company snapshot.

Each refusal is judged as the filter's are: the clock port is something the TV needs, so a refusal there
comes first; an unusual port, an address the gate refused, or an address of the owner's own block list is
a likely cause when the record has not seen it refused before ("first sight"); a wall the gateway keeps on
purpose (QUIC, the encrypted lookups, the home network, LG's ports, tunnels, large pings, the gateway's own
services) never is, since an app falls back from it or it is the isolation itself. Structural drops (a
forged source, the wrong uplink) are `tvgw doctor`'s, not a refused name's, and are left out.

Everything that decides is a pure function of what was read (`judge`); `read_live` is the only part that
touches the gateway, and the unit tests stand it in.
"""

from __future__ import annotations

import re
import shutil
import sqlite3
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

from tvgw import companies, ingest, queries, verify

# the tables whose refusing rules are read, as tvgw-apply loads them
TABLES = (("inet", "tvgw"), ("inet", "tvgw_gate"))
HISTORY_DAYS = 14  # how far back "refused before" reaches for a refusal the store holds no sample of
# the sampled prefixes, as tvgw-apply's log rules write them; one journal read takes them all
PREFIXES = ("tvgw-oddport", "tvgw-ntp", "tvgw-adport", "tvgw-gate")
_SAMPLE = re.compile(r"(tvgw-[a-z]+): ")
_DST = re.compile(r"\bDST=([0-9.]+)\b")
_PROTO = re.compile(r"\bPROTO=([A-Z0-9]+)\b")
_DPT = re.compile(r"\bDPT=(\d+)\b")
STRICT_ON = "STRICT_PORTS:"  # the reject's comment begins so; the count-only accept's with STRICT_PORTS=no
STRICT_OFF = "STRICT_PORTS=no"


@dataclass(frozen=True)
class Kind:
    """One wall of the firewall, as the report speaks of it."""

    key: str
    comment: str  # the counter's comment begins with this; '' for a wall with samples only
    prefix: str  # its log sample's prefix; '' for a wall with a counter only
    name: str  # what was refused, in plain words, when the line is about the wall as a whole
    note: str  # why the wall is there, or what follows from it, in a clause
    on_purpose: bool  # the gateway's isolation itself, or a wall an app falls back from
    tracking: bool = False
    needed: str | None = None  # why the TV needs what it refused, when it does
    what: str = ""  # what refused it, in plain words, for a likely cause
    fix: str = ""  # how to let it through, for a likely cause (and for every line with --all)
    unit: str = "time"  # a reject is one refusal a try; a drop is counted in packets
    per_dest: bool = False  # one line for each destination its samples name


KINDS = (
    Kind(
        "clock",
        "clock port",
        "tvgw-ntp",
        "the clock port (NTP, UDP port 123)",
        "the TV asks a clock server for the time over it",
        False,
        needed="the TV asked a clock server for the time, and a wrong clock breaks its secure connections",
        what="the clock port rule (CLOCK_PORT in /etc/tvgw/tvgw.conf, or the profile's [firewall] ntp)",
        fix="set CLOCK_PORT=any in /etc/tvgw/tvgw.conf, then run sudo tvgw-apply",
        per_dest=True,
    ),
    Kind(
        "oddport",
        STRICT_ON,
        "tvgw-oddport",
        "unusual ports",
        "STRICT_PORTS=yes refuses every port but the web, the clock and DNS",
        False,
        what="STRICT_PORTS=yes, which refuses every port but the web, the clock and DNS",
        fix=(
            "if the app needs that port, set STRICT_PORTS=no in /etc/tvgw/tvgw.conf, then run sudo tvgw-apply"
        ),
        per_dest=True,
    ),
    Kind(
        "gate",
        "",
        "tvgw-gate",
        "addresses no lookup returned",
        "the address gate refuses an address none of the TV's lookups returned",
        False,
        what="the address gate (DNSGATE in /etc/tvgw/tvgw.conf)",
        fix="set DNSGATE=count in /etc/tvgw/tvgw.conf, then run sudo tvgw-apply",
        per_dest=True,
    ),
    Kind(
        "block4",
        "manual IP blocks",
        "",
        "addresses on your own block list (/etc/tvgw/block4.txt)",
        "you listed them",
        False,
        what="your own block list, /etc/tvgw/block4.txt",
        fix="take the address out of /etc/tvgw/block4.txt, then run sudo tvgw-apply",
    ),
    Kind(
        "adport",
        "LG adtech port",
        "",
        "LG's advertising and viewing-data ports",
        "LG's advertising and screen-recognition traffic",
        True,
        tracking=True,
        fix="ADTECH_PORT_WALL=no in /etc/tvgw/tvgw.conf, then sudo tvgw-apply",
    ),
    Kind(
        "quic",
        "QUIC",
        "",
        "QUIC (UDP port 443)",
        "apps fall back to an ordinary secure connection, whose name the gateway can see",
        True,
        fix="BLOCK_QUIC=no in /etc/tvgw/tvgw.conf, then sudo tvgw-apply",
    ),
    Kind(
        "dot",
        "DoT/DoQ",
        "",
        "encrypted lookups around the filter (DNS over TLS or QUIC)",
        "the TV's lookups still reach the gateway's filter",
        True,
    ),
    Kind(
        "doh",
        "DoH resolvers",
        "",
        "encrypted lookups at public resolvers (DNS over HTTPS)",
        "the TV's lookups still reach the gateway's filter",
        True,
    ),
    Kind(
        "lan",
        "TV may not reach the home LAN",
        "",
        "connections to your home network",
        "the gateway keeps the TV off it, so an app that plays from or casts to a device at home stops here",
        True,
        unit="packet",
    ),
    Kind(
        "tunnel",
        "no GRE/ESP/6in4",
        "",
        "tunnels (a VPN)",
        "nothing may go around the gateway",
        True,
        unit="packet",
    ),
    Kind("icmp", "no ICMP tunnels", "", "large pings", "only small pings pass", True, unit="packet"),
    Kind(
        "pi",
        "TV may not reach other Pi services",
        "",
        "the gateway computer's other services",
        "the TV may use only its resolver and its web ports",
        True,
        unit="packet",
    ),
    Kind(
        "pi_addr",
        "TV talks to the gateway address only",
        "",
        "the gateway computer's other addresses",
        "the TV may use only its resolver and its web ports",
        True,
        unit="packet",
    ),
)
BY_KEY = {k.key: k for k in KINDS}


@dataclass(frozen=True)
class Sample:
    t: float
    prefix: str
    proto: str
    dst: str
    dport: int | None


@dataclass
class Reading:
    """What `read_live` found on the gateway. `live` maps each counted comment to its packets now;
    `reloads` is tvgw-apply's listing pair either side of its last reload, as (its time, the counts);
    `samples` are the window's log samples, oldest first; `errors` says what could not be read."""

    live: dict[str, int] = field(default_factory=dict)
    reloads: list[tuple[float, dict[str, int]]] = field(default_factory=list)
    samples: list[Sample] = field(default_factory=list)
    gate_refuses: bool = False  # the settings the gate was applied with refuse (DNSGATE=enforce, someday)
    counters_read: bool = False
    samples_read: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass
class Wall:
    """One line of the report about the firewall: a wall, or one destination one refused."""

    key: str
    name: str
    count: int  # refusals (or packets, for a drop) in the counted window
    first: float  # when the count starts: its first sample, else the counter's starting point
    last: float
    since: float | None  # the counter's starting point; None when it counts from the samples alone
    at_least: bool = False  # the samples are a lower bound (the rule logs at most six a minute)
    first_sight: bool = True
    prior: float | None = None  # its newest refusal before the window, where the record says
    let_through: float | None = None  # (an unusual port) when the TV last used it while it was let through
    before: int = 0  # (a wall counted, not sampled) what it refused in the HISTORY_DAYS before the count
    company: str | None = None
    domain: str = ""  # what first sight was judged on, in words

    @property
    def kind(self) -> Kind:
        return BY_KEY[self.key]

    @property
    def needed(self) -> str | None:
        return self.kind.needed

    @property
    def tracking(self) -> bool:
        return self.kind.tracking

    @property
    def on_purpose(self) -> bool:
        return self.kind.on_purpose

    @property
    def likely(self) -> bool:
        """The clock port always; the others when the record has not seen them refused before and the
        wall is not one the gateway keeps on purpose."""
        return self.needed is not None or (self.first_sight and not self.on_purpose)

    @property
    def lookups(self) -> int:  # the DNS names' word, so the report ranks both alike
        return self.count

    @property
    def last_allowed(self) -> float | None:
        return self.let_through

    @property
    def fix(self) -> str:
        return self.kind.fix


# ---- reading the gateway --------------------------------------------------------------------------------


def counts_of(listings: list[str]) -> dict[str, int]:
    """{comment: packets} over `nft -j list table` listings, rules sharing a comment summed."""
    out: dict[str, int] = {}
    for text in listings:
        for comment, packets, _bytes in verify.counters_from_table(text):
            out[comment] = out.get(comment, 0) + packets
    return out


def reload_pair(read: Callable[[str], str], mtime: Callable[[str], float | None]) -> list[tuple[float, dict]]:
    """tvgw-apply's two listings either side of its last reload, as verify reads them: both or neither,
    the after newer than the before."""
    pair = [(mtime(path), read(path)) for path in verify.RELOADS]
    (t0, before), (t1, after) = pair
    if t0 is None or t1 is None or t1 <= t0 or not before.strip() or not after.strip():
        return []
    return [(t, counts_of(text.splitlines())) for t, text in pair if t is not None]


def parse_samples(lines: list[str], since: float, until: float) -> list[Sample]:
    """The journal's lines (`short-unix`) as samples in [since, until), oldest first."""
    out = []
    for line in lines:
        try:
            t = float(line.split(" ", 1)[0])
        except (ValueError, IndexError):
            continue
        m = _SAMPLE.search(line)
        if not m or m.group(1) not in PREFIXES or not since <= t < until:
            continue
        dst, proto, dpt = _DST.search(line), _PROTO.search(line), _DPT.search(line)
        out.append(
            Sample(
                t,
                m.group(1),
                proto.group(1).lower() if proto else "",
                dst.group(1) if dst else "",
                int(dpt.group(1)) if dpt else None,
            )
        )
    return sorted(out, key=lambda x: x.t)


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20
        )
        return out.returncode, out.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def read_live(
    since: float,
    until: float,
    run: Callable[[list[str]], tuple[int, str]] = _run,
    read: Callable[[str], str] = _read,
    mtime: Callable[[str], float | None] = verify.file_mtime,
    journal: Callable[[str], list[str]] | None = None,
) -> Reading | None:
    """The firewall's counters now, the apply's listing pair, and the window's samples from the kernel
    journal. None on a computer with no nft at all, which is not a gateway: there is nothing to say."""
    if shutil.which("nft") is None and run is _run:
        return None
    r = Reading()
    listings = []
    for table in TABLES:
        rc, text = run(["nft", "-j", "-t", "list", "table", *table])
        if rc == 0 and text.strip():
            listings.append(text)
        elif table == TABLES[0]:
            r.errors.append(f"nft could not list table {' '.join(table)}")
    r.live = counts_of(listings)
    r.counters_read = bool(listings)
    r.reloads = reload_pair(read, mtime)
    applied = read(verify.SETTINGS_APPLIED)
    r.gate_refuses = any(line.strip() == "DNSGATE=enforce" for line in applied.splitlines())
    pattern = "(" + "|".join(PREFIXES) + "): "
    try:
        lines = (journal or (lambda s: ingest.journal_kernel_lines(s, pattern)))(f"@{int(since)}")
        r.samples = parse_samples(lines, since, until)
        r.samples_read = True
    except (OSError, RuntimeError, subprocess.SubprocessError) as e:
        r.errors.append(f"the kernel journal could not be read ({e})"[:200])
    return r


# ---- counting the window ----------------------------------------------------------------------------------


def window_counts(
    conn: sqlite3.Connection | None, since: float, now: float, r: Reading
) -> tuple[dict[str, int], float | None]:
    """({comment: refusals in the window}, when the count starts). The newest snapshot the store holds at
    or before `since`, within queries.FW_BASELINE, is the starting point; then each snapshot after it, the
    apply's listing pair when it is newer than the last of them, and the live counters, in that order.
    Each step is the rise, or the whole count after a fall (a reload set it to zero); a comment the step
    before did not have is new, and its whole count is the window's. With no snapshot to start from, the
    apply's after-listing is the start (the counters were zero then); with neither, None: no count."""
    points: list[tuple[float, dict[str, int]]] = []
    if conn is not None:
        try:
            base_t = conn.execute(
                "SELECT MAX(t) FROM fw_counters WHERE t <= ? AND t >= ?", (since, since - queries.FW_BASELINE)
            ).fetchone()[0]
            if base_t is not None:
                points.append((base_t, {}))
                for t, rule, packets, _row in conn.execute(
                    "SELECT t, rule, SUM(packets), MIN(rowid) FROM fw_counters WHERE t >= ? AND t <= ?"
                    " GROUP BY rule, t ORDER BY MIN(rowid)",
                    (base_t, now),
                ):
                    if points[-1][0] != t:
                        points.append((t, {}))
                    points[-1][1][rule] = int(packets or 0)
        except sqlite3.Error:
            points = []
    last = points[-1][0] if points else None
    for t, counts in r.reloads:
        if last is None or t > last:
            points.append((t, counts))
    if not points:
        return {}, None
    if last is None:  # no snapshot: from the apply's after-listing, which is where the counts began
        points = points[-1:]
    points.append((now, r.live))
    start, prev = points[0][0], dict(points[0][1])
    acc: dict[str, int] = {}
    for _t, counts in points[1:]:
        for rule, n in counts.items():
            was = prev.get(rule)
            step = n if was is None or n < was else n - was
            if step:
                acc[rule] = acc.get(rule, 0) + step
            prev[rule] = n
    return acc, start


def _kind_count(counts: dict[str, int], kind: Kind) -> int:
    return sum(n for rule, n in counts.items() if kind.comment and rule.startswith(kind.comment))


# ---- judging ---------------------------------------------------------------------------------------------


def _history(conn: sqlite3.Connection | None, sql: str, args: tuple) -> float | None:
    if conn is None:
        return None
    try:
        row = conn.execute(sql, args).fetchone()
    except sqlite3.Error:
        return None
    return row[0] if row else None


def strict_since(conn: sqlite3.Connection | None) -> float | None:
    """When STRICT_PORTS=yes began, as the counters show it: the first snapshot of the strict reject
    after the last one of the count-only accept. None when the store shows neither."""
    off = _history(conn, "SELECT MAX(t) FROM fw_counters WHERE rule LIKE ?", (STRICT_OFF + "%",))
    return _history(
        conn,
        "SELECT MIN(t) FROM fw_counters WHERE rule LIKE ? AND t > ?",
        (STRICT_ON + "%", off if off is not None else 0.0),
    )


def _named(conn: sqlite3.Connection | None, dsts: list[str], now: float) -> dict[str, dict[str, float]]:
    if conn is None or not dsts:
        return {d: {} for d in dsts}
    try:
        return queries._answered(conn, dsts, now - queries.KNOWN_DAYS * 86400, now)
    except sqlite3.Error:
        return {d: {} for d in dsts}


def judge(
    r: Reading, conn: sqlite3.Connection | None, since: float, now: float
) -> tuple[list[Wall], float | None]:
    """(the walls' lines, when their counts start). A wall counts only while its refusing rule is loaded:
    an unusual port's samples are refusals only with the strict reject in the live listing, and the gate's
    only once its settings refuse. sqlite3.Error from the store is taken as no history."""
    counts, start = window_counts(conn, since, now, r)
    present = set(r.live)
    strict = any(c.startswith(STRICT_ON) for c in present)
    clock = any(c.startswith(BY_KEY["clock"].comment) for c in present)
    by_prefix: dict[str, list[Sample]] = {}
    for x in r.samples:
        by_prefix.setdefault(x.prefix, []).append(x)
    walls: list[Wall] = []
    on_since = strict_since(conn) if strict else None
    for kind in KINDS:
        live = (
            (kind.key == "oddport" and strict)
            or (kind.key == "clock" and clock)
            or (kind.key == "gate" and r.gate_refuses)
            or kind.key not in ("oddport", "clock", "gate")
        )
        if not live:
            continue
        total = _kind_count(counts, kind)
        samples = by_prefix.get(kind.prefix, []) if kind.per_dest else []
        if kind.per_dest and samples:
            walls += _per_dest(kind, samples, total, conn, since, now, on_since)
            continue
        if not total:
            continue
        earlier = 0
        if kind.comment and conn is not None:
            try:
                history = queries.fw_activity(conn, now - HISTORY_DAYS * 86400, start or since)
            except sqlite3.Error:
                history = []
            earlier = sum(n for rule, n in history if rule.startswith(kind.comment))
        t0 = start if start is not None else since
        walls.append(
            Wall(kind.key, kind.name, total, t0, now, start, first_sight=not earlier, before=earlier)
        )
    return walls, start


def _per_dest(
    kind: Kind,
    samples: list[Sample],
    total: int,
    conn: sqlite3.Connection | None,
    since: float,
    now: float,
    on_since: float | None,
) -> list[Wall]:
    """One line for each destination the samples name: (protocol, port, address) for an unusual port, the
    address for the clock port and the gate. Its count is its samples, a lower bound when the counter
    counted more than all the samples together."""
    groups: dict[tuple, list[Sample]] = {}
    for x in samples:
        key = (x.proto, x.dport, x.dst) if kind.key == "oddport" else (x.dst,)
        groups.setdefault(key, []).append(x)
    names = _named(conn, sorted({x.dst for x in samples if x.dst}), now)
    under = total > len(samples)
    out = []
    for xs in groups.values():
        dst = xs[0].dst
        answered = sorted(names.get(dst, {}), key=lambda q: -names[dst][q])
        label = f" ({answered[0]})" if answered else ""
        company = companies.company(answered[0]) if answered else None
        w = Wall(kind.key, "", len(xs), xs[0].t, xs[-1].t, None, at_least=under, company=company)
        if kind.key == "oddport":
            proto, dport = xs[0].proto, xs[0].dport
            w.name = f"{proto.upper()} port {dport} at {dst}{label}"
            w.domain = f"{proto.upper()} port {dport}"
            prior = _history(
                conn,
                "SELECT MAX(t) FROM oddport WHERE lower(proto) = ? AND dport = ? AND t < ?",
                (proto, dport, since),
            )
            if prior is None:
                w.first_sight = True
            elif on_since is not None and prior < on_since:
                w.first_sight, w.let_through = True, prior  # it was let through then: a change
            else:
                w.first_sight, w.prior = False, prior
        elif kind.key == "clock":
            w.name = f"the clock port (NTP) at {dst}{label}"
            w.domain = "the clock port"
        else:  # the gate
            w.name = f"{dst}{label}, an address no lookup returned"
            w.domain = dst
            prior = _history(conn, "SELECT MAX(t) FROM gate WHERE dst = ? AND t < ?", (dst, since))
            w.first_sight, w.prior = prior is None, prior
        out.append(w)
    return out


def store_start(conn: sqlite3.Connection | None) -> float | None:
    """Where the firewall's record begins: its first counter snapshot."""
    return _history(conn, "SELECT MIN(t) FROM fw_counters", ())


def note(r: Reading | None) -> list[str]:
    """What weakens the firewall's half of the report, in plain words."""
    if r is None:
        return []
    out = []
    if not r.counters_read:
        out.append(
            "The firewall's own counters could not be read ("
            + "; ".join(e for e in r.errors if e.startswith("nft"))
            + "), so what it refused is not shown."
        )
    if not r.samples_read:
        out.append(
            "The kernel journal could not be read, so the firewall's refusals are counted but their"
            " destinations are not named."
        )
    return out
