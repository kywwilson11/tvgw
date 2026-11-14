"""(acr) Synthetic flows for the ACR upload detector, generated from published summary statistics only.

The *Watching the Watchers* LG trace is CC BY-NC-ND 4.0, so no row of it, and nothing derived from its
rows, may enter the repository (docs/research/state-of-the-art-2026-11.md, section 17). Every number below
is a summary statistic printed in docs/research/deep-dive-2026-11/13-gap-reconcile-the-two-incompatible-
acr-detec.md, sections 1.1, 1.3, 1.6 and 1.7, and each constant says which. The rest is drawn from a seeded
`random.Random`, so a fixture is reproducible, is ours, and owes the trace nothing but its published shape.

A generator returns `Flow`s as tvgw stores them: conntrack's byte counts include 40 header bytes per
packet (`queries.HEADER_BYTES`), so each flow carries its payload plus the headers of the packets that
carried it and of the acknowledgements the other side's data drew. `insert` writes the flows, and for a
named flow the TLS hello that names it, into a store. Addresses are documentation ranges; the vendor host
names are the ones the profile already carries."""

from __future__ import annotations

import itertools
import math
import random
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass

from tvgw.msgtap import SEQ_SPAN, Packet

MSS = 1448  # TCP payload per full segment on a 1500-byte path
HEADER = 40  # IPv4 + TCP header bytes conntrack counts per packet (queries.HEADER_BYTES)
HANDSHAKE = 4  # packets each way that carry no payload: SYN or SYN-ACK, the last ACK, FIN, its ACK
FIN_LINGER = 120  # s: conntrack destroys a FIN-closed entry after TIME_WAIT (13, 1.1, item 2)

# ---- lg_acr_day and lg_acr_stub (13, 1.7, from 1.1 and 1.3) ----
ACR_PORT = 4431  # every ACR connection used 4431, 4445 or 4447; fingerprints ride 4431 (13, 1.6)
ACR_NAMES = tuple(f"tkacr6{n:02d}.alphonso.tv" for n in range(41))  # "41 rotating" fingerprint names
ACR_SERVERS = tuple(f"203.0.113.{40 + i}" for i in range(8))  # one /24, as an unnamed cell sees them
AWAKE_HOURS = 14.0  # hours of a TV day with the set on
CONNECT_GAPS = ((56, 0.15), (60, 0.45), (120, 0.25), (180, 0.15))  # s between opens, and their weights
FINGERPRINT_SHARE = 1 / 3  # one open in three is a fingerprint connection, the rest heartbeats
FP_DURATION = (113.0, 0.8, 950.0)  # s: lognormal median and sigma, and the cap (1.1: median 113, max 951)
FP_BURSTS = (3, 9)  # fingerprint uploads per connection: median and p90 (1.3), drawn lognormal
BURST_EVERY = (14.0, 1.0)  # s: one fingerprint upload every 14 s +- 1 inside a connection (1.1)
BURST_PAYLOAD = (22_000, 3_000)  # bytes: N(22 KB, 3 KB) per fingerprint upload (1.3: median 22.1 KB)
BURST_FLOOR = 2_000  # bytes: 1.1 counts an upload as a burst from 2 KB
DOWN_DIVISOR = (8.0, 17.0)  # down = up / U(8, 17) on a fingerprint connection (1.1: 7-17x up:down)
HEARTBEAT_UP = (1_100, 1_800)  # bytes of payload up on a heartbeat connection
HEARTBEAT_DOWN = 3_000  # bytes of payload down on one
# the 04-22 row of 1.1: a 90-minute stub of a day, 52 connections, 6 of them fingerprint, 0.7 MB up
STUB_MINUTES = 90
STUB_CONNS = 52
STUB_FINGERPRINTS = 6
STUB_BURSTS = 6  # bursts per stub fingerprint connection: 84 s, inside 1.1's IQR of 46-165 s
STUB_RATIO = 6.8  # the row's up:down. 0.7 MB / 6.8 is about 103 KB down in all, half of it on the six
STUB_HEARTBEAT_DOWN = 1_000  # fingerprint connections, which leaves about 1 KB for each heartbeat

# ---- imc_fingerprint_hour (13, 1.3: IMC 2024's tables are frame bytes, both ways, per one-hour run) ----
IMC_HOUR_FRAMES = (4_125_000, 4_948_300)  # US LG, logged in and opted in: HDMI 4,125.0 KB to FAST 4,948.3 KB
IMC_EVERY = 60.0  # s between fingerprint connections: the client's connection timer (1.1)
IMC_BURSTS = 3  # uploads per connection: the trace's median (1.3), so about 180 in the hour (at most 216)
ETHERNET = 14  # bytes of Ethernet header per frame, which IMC's frame.len counts and conntrack does not
FULL_FRAME = 1_514  # a full-size frame: 1,448 bytes of payload, TCP with timestamps, IPv4 and Ethernet

# ---- lg_control_plane (13, 1.5 and 1.7) ----
CONTROL_NAMES = ("prov-lg.alphonso.tv", "bl-server.alphonso.tv", "clockskew.alphonso.tv")
CONTROL_SERVER = "203.0.113.60"
CONTROL_EVERY = 1_140.0  # s, +- 1 %: the three names are looked up together on this timer
CONTROL_UP = 1_200  # bytes up per control-plane connection
CONTROL_DOWN = (3_700, 6_800)  # bytes down per connection

# ---- the ones that must stay silent, or fire only hourly (13, 1.2 and 1.7) ----
STREAMING_NAME = "www.youtube.com"  # Streaming, an expected category in lg-webos
STREAMING_SERVER = "198.51.100.20"
STREAMING_CONNS = 250
STREAMING_UP = 11_800_000  # bytes up over the day, YouTube's best lab day
STREAMING_RATIO = 3.07  # its up:down: 77 % of the 4x threshold
VIDEO_NAME = "rr1---sn-example.googlevideo.com"  # the video itself: all down
TELEMETRY_NAME = "collector.telemetry.example.com"  # an unexpected category (Other)
TELEMETRY_CONNS = 9
TELEMETRY_UP = 961_000  # bytes up in one hour, at 20x the bytes down
TELEMETRY_RATIO = 20.0
MQTT_NAME = "qs2-nevoai-iothub-12-prod.azure-devices.net"  # 13, 1.6: the lab's Nevo hub on 8883
MQTT_SECONDS = 3_758  # one connection a day, its median length
MQTT_KB_PER_MINUTE = 0.02
FIRMWARE_BYTES = 400_000_000  # bytes down; the TV sends acknowledgements only


@dataclass(frozen=True)
class Flow:
    t_start: float
    t_end: float
    dst: str
    dport: int
    sport: int
    bytes_up: int
    pkts_up: int
    bytes_down: int
    pkts_down: int
    sni: str | None = None

    @property
    def payload_up(self) -> int:
        return max(0, self.bytes_up - HEADER * self.pkts_up)

    @property
    def payload_down(self) -> int:
        return max(0, self.bytes_down - HEADER * self.pkts_down)


def ports(first: int = 20_000) -> Iterator[int]:
    """TV source ports, never reused within a fixture, so each flow's hello names it alone."""
    return (20_000 + (n % 40_000) for n in itertools.count(first - 20_000))


def segments(payload: int) -> int:
    return math.ceil(payload / MSS) if payload > 0 else 0


def connection(
    t: float,
    seconds: float,
    dst: str,
    dport: int,
    sport: int,
    sends_up: list[int],
    sends_down: list[int],
    sni: str | None,
) -> Flow:
    """One TCP connection as conntrack reports it: each send is cut into full segments, each send from the
    other side draws one acknowledgement, and the handshake and close add HANDSHAKE packets each way.
    The entry is destroyed FIN_LINGER seconds after the last packet."""
    pkts_up = sum(segments(x) for x in sends_up) + len(sends_down) + HANDSHAKE
    pkts_down = sum(segments(x) for x in sends_down) + len(sends_up) + HANDSHAKE
    return Flow(
        t_start=t,
        t_end=t + seconds + FIN_LINGER,
        dst=dst,
        dport=dport,
        sport=sport,
        bytes_up=sum(sends_up) + HEADER * pkts_up,
        pkts_up=pkts_up,
        bytes_down=sum(sends_down) + HEADER * pkts_down,
        pkts_down=pkts_down,
        sni=sni,
    )


def _gap(rng: random.Random) -> float:
    gaps, weights = zip(*CONNECT_GAPS, strict=True)
    return float(rng.choices(gaps, weights)[0])


def _fingerprint(rng: random.Random, t: float, sport: int, bursts: int | None, named: bool) -> Flow:
    """A fingerprint connection: `bursts` uploads (else drawn with FP_BURSTS' median and p90) 14 s +- 1
    apart, inside a connection whose length is drawn from FP_DURATION and never shorter than they are."""
    median, sigma, cap = FP_DURATION
    if bursts is None:
        mid, p90 = FP_BURSTS
        spread = math.log(p90 / mid) / 1.2816  # the lognormal sigma whose 90th percentile is p90
        bursts = max(1, min(int(cap // BURST_EVERY[0]), round(rng.lognormvariate(math.log(mid), spread))))
    gaps = [
        rng.uniform(BURST_EVERY[0] - BURST_EVERY[1], BURST_EVERY[0] + BURST_EVERY[1])
        for _ in range(bursts - 1)
    ]
    seconds = min(cap, max(sum(gaps) + 1, rng.lognormvariate(math.log(median), sigma)))
    up = [max(BURST_FLOOR, round(rng.gauss(*BURST_PAYLOAD))) for _ in range(bursts)]
    divisor = rng.uniform(*DOWN_DIVISOR)
    down = [round(x / divisor) for x in up]
    name = rng.choice(ACR_NAMES)
    return connection(t, seconds, rng.choice(ACR_SERVERS), ACR_PORT, sport, up, down, name if named else None)


def _heartbeat(
    rng: random.Random, t: float, sport: int, named: bool, down_bytes: int = HEARTBEAT_DOWN
) -> Flow:
    name = rng.choice(ACR_NAMES)
    up, down = [rng.randint(*HEARTBEAT_UP)], [down_bytes]
    return connection(t, 2.0, rng.choice(ACR_SERVERS), ACR_PORT, sport, up, down, name if named else None)


def lg_acr_day(
    rng: random.Random, start: float, hours: float = AWAKE_HOURS, named: bool = True
) -> list[Flow]:
    """LG's ACR client with Live Plus on, for `hours` from `start`: a connection on the CONNECT_GAPS timer,
    one in three a fingerprint connection uploading a burst every 14 s, the rest heartbeats. With
    `named=False` no hello names them, as when the capture missed every one."""
    sports, out, t = ports(30_000), [], start
    while t < start + hours * 3600:
        if rng.random() < FINGERPRINT_SHARE:
            out.append(_fingerprint(rng, t, next(sports), None, named))
        else:
            out.append(_heartbeat(rng, t, next(sports), named))
        t += _gap(rng)
    return out


def imc_fingerprint_hour(rng: random.Random, hour: float, named: bool = True) -> list[Flow]:
    """(budget) One clock hour of LG's ACR as IMC 2024 measured it (13, 1.3: 4,125 to 4,948 KB of Ethernet
    frames, both directions, in a one-hour run on HDMI, antenna or FAST): a fingerprint connection every
    IMC_EVERY seconds from the hour's start, each carrying IMC_BURSTS uploads of the trace's size 14 s
    apart, so the hour's frames land inside IMC's range (tests/unit/test_upload_budget.py checks it)."""
    sports = ports(38_000)
    opens = [hour + 1 + i * IMC_EVERY + rng.uniform(0, 2) for i in range(int(3600 // IMC_EVERY))]
    return [_fingerprint(rng, t, next(sports), IMC_BURSTS, named) for t in opens]


def imc_corner_hour(
    hour: float, ratio: float, frames: int = IMC_HOUR_FRAMES[0], conns: int = 60
) -> list[Flow]:
    """(budget) The corner budget.ACR_HOUR_NET is estimated at: `frames` bytes of Ethernet frames both
    ways in one clock hour (IMC 2024's quietest fingerprinting hour by default) at `ratio` up to down,
    every frame full-size (FULL_FRAME), the down side too, so the down side's payload bound is as large
    as those frames allow and the net as small. 7 is the trace's lowest ratio on the fingerprint port,
    4.5 its lowest domain-wide (13, 1.2)."""
    n_up = round(frames * ratio / (ratio + 1) / FULL_FRAME)
    n_down = round(frames / (ratio + 1) / FULL_FRAME)
    sports, out = ports(39_000), []
    for i in range(conns):
        up = n_up // conns + (i < n_up % conns)
        down = n_down // conns + (i < n_down % conns)
        t = hour + 1 + i * 59
        out.append(
            Flow(
                t_start=t,
                t_end=t + 60 + FIN_LINGER,
                dst=ACR_SERVERS[i % len(ACR_SERVERS)],
                dport=ACR_PORT,
                sport=next(sports),
                bytes_up=up * (FULL_FRAME - ETHERNET),
                pkts_up=up,
                bytes_down=down * (FULL_FRAME - ETHERNET),
                pkts_down=down,
                sni=ACR_NAMES[i % len(ACR_NAMES)],
            )
        )
    return out


def frame_bytes(flows: list[Flow]) -> int:
    """(budget) The flows as IMC 2024 counted them: frame bytes both ways, conntrack's IP bytes plus the
    14-byte Ethernet header of every packet."""
    return sum(f.bytes_up + f.bytes_down + ETHERNET * (f.pkts_up + f.pkts_down) for f in flows)


def lg_acr_stub(rng: random.Random, hour: float, named: bool = True) -> list[Flow]:
    """The 90-minute stub of a day (1.1's 04-22 row): STUB_CONNS connections spread from half an hour
    before the clock hour `hour` to its end, STUB_FINGERPRINTS of them, all inside that hour, uploading
    fingerprints, so the day stays under ACR_DAILY's megabyte while the hour passes ACR_HOURLY."""
    start = hour - (STUB_MINUTES - 60) * 60
    step = STUB_MINUTES * 60 / STUB_CONNS
    opens = [start + i * step + rng.uniform(0, 5) for i in range(STUB_CONNS)]
    inside = [i for i, t in enumerate(opens) if hour <= t < hour + 3600 - 120]
    chosen = set(rng.sample(inside, STUB_FINGERPRINTS))
    sports = ports(36_000)
    return [
        _fingerprint(rng, t, next(sports), STUB_BURSTS, named)
        if i in chosen
        else _heartbeat(rng, t, next(sports), named, STUB_HEARTBEAT_DOWN)
        for i, t in enumerate(opens)
    ]


def lg_control_plane(
    rng: random.Random, start: float, hours: float = AWAKE_HOURS, with_4001: bool = True
) -> tuple[list[Flow], list[tuple]]:
    """Alphonso's control plane, whatever the ACR state: the three CONTROL_NAMES looked up together every
    CONTROL_EVERY seconds, then one connection on 443 and one on 4001 (with `with_4001`; the port wall
    leaves no flow for the second). Returns the flows and the A lookups as dns rows
    (t, qname, qtype, answers, blocked)."""
    sports, flows, lookups, t = ports(40_000), [], [], start
    while t < start + hours * 3600:
        lookups += [(t, name, "A", f"A:{CONTROL_SERVER}", 0) for name in CONTROL_NAMES]
        for dport in (443, 4001) if with_4001 else (443,):
            down = [rng.randint(*CONTROL_DOWN)]
            flows.append(
                connection(
                    t + 1, 32.0, CONTROL_SERVER, dport, next(sports), [CONTROL_UP], down, CONTROL_NAMES[0]
                )
            )
        t += CONTROL_EVERY * rng.uniform(0.99, 1.01)
    return flows, lookups


def streaming_day(rng: random.Random, start: float, named: bool = True) -> list[Flow]:
    """A day of YouTube: STREAMING_CONNS API connections carrying STREAMING_UP bytes up at STREAMING_RATIO,
    the heaviest uploader the lab set saw outside ACR, and the video itself, gigabytes down with only
    acknowledgements up, from another /24 so each cell is judged on its own."""
    sports, out = ports(44_000), []
    per_up = STREAMING_UP // STREAMING_CONNS
    for i in range(STREAMING_CONNS):
        t = start + i * (AWAKE_HOURS * 3600 / STREAMING_CONNS)
        up = per_up + rng.randint(-2_000, 2_000)
        down = round(up / STREAMING_RATIO)
        sni = STREAMING_NAME if named else None
        out.append(connection(t, 30.0, STREAMING_SERVER, 443, next(sports), [up], [down], sni))
    for i in range(40):  # 40 video segments of ~50 MB each
        t = start + i * 1200
        chunks = [MSS * 64] * 540
        sni = VIDEO_NAME if named else None
        out.append(connection(t, 600.0, "192.0.2.30", 443, next(sports), [300], chunks, sni))
    return out


def telemetry_burst(rng: random.Random, hour: float) -> list[Flow]:
    """An upload-heavy telemetry hour on a name outside the expected categories: TELEMETRY_CONNS
    connections, TELEMETRY_UP bytes up at TELEMETRY_RATIO. Too few connections for a day; one hour's
    worth for the hourly test, which is a true ACR-shaped alarm on a telemetry name."""
    sports, out = ports(48_000), []
    for i in range(TELEMETRY_CONNS):
        up = TELEMETRY_UP // TELEMETRY_CONNS + rng.randint(0, 50)
        down = round(up / TELEMETRY_RATIO)
        out.append(
            connection(
                hour + 300 + i * 360, 20.0, "198.51.100.40", 443, next(sports), [up], [down], TELEMETRY_NAME
            )
        )
    return out


def mqtt_long(start: float) -> list[Flow]:
    """The lab's Nevo IoT hub session on 8883: one long, nearly silent connection a day."""
    up = round(MQTT_SECONDS / 60 * MQTT_KB_PER_MINUTE * 1000)
    return [connection(start, MQTT_SECONDS, "198.51.100.50", 8883, 50_000, [up], [up], MQTT_NAME)]


def hue_style_poller(rng: random.Random, start: float, hours: float = 4.0) -> list[Flow]:
    """Two timers that look like a beacon and are not ACR: a captive-portal probe every 30 s and a
    bridge-discovery poll every 90 s, each moving 0.2-1.1 KB, under names outside the expected
    categories. A periodic connection, and nothing more (13, 1.2: a 10-200 s timer marks 15 other
    domains in the lab set)."""
    sports, out = ports(52_000), []
    for name, dst, every in (
        ("portal.example.net", "198.51.100.60", 30),
        ("bridge.example.org", "198.51.100.61", 90),
    ):
        t = start
        while t < start + hours * 3600:
            out.append(connection(t, 1.0, dst, 443, next(sports), [rng.randint(200, 1_100)], [400], name))
            t += every * rng.uniform(0.97, 1.03)
    return out


def firmware_download(start: float) -> list[Flow]:
    """A firmware image: FIRMWARE_BYTES down from an address no hello named, the TV's side all ACKs."""
    chunks = [MSS] * (FIRMWARE_BYTES // MSS)
    return [connection(start, 900.0, "203.0.113.90", 443, 56_000, [], chunks, None)]


# ---- (msgtap) the same clients as a capture of the TV's data packets holds them ----
# The message tap's proof of concept (pass 6) judged classes of an hour, each a client on connections of
# its own: LG's fingerprint uploads inside one connection, also with some never sent; an app's own
# interface host; and an analytics library that flushes a batch on a timer. The fingerprint client's
# numbers are 1.1's and 1.3's above; the other two are made up to be what a fingerprint is not. A
# connection's writes are (moment, bytes), and `tap_hour` cuts them into packets.
TAP_SERVER = "203.0.113.70"  # every class's server: the TV's port tells the connections apart
TAP_NAME = "api.screen.example.com"  # outside every category, so the upload test judges it
SEGMENT_GAP = (0.0002, 0.002)  # s between the segments of one write
APP_HEARTBEAT = (30.0, 0.5, (900, 1_800))  # s apart, its sd, and bytes: small, on a timer
APP_REQUESTS = ((2.0, 4.0, 6.0), 0.05, (450, 950))  # a player's requests: s apart, sd, bytes
APP_TELEMETRY = (20.0, (9.1, 1.0), 400_000)  # s apart on average, at random; lognormal bytes; their cap
SDK_FLUSH = (30.0, 3.0, (9.6, 0.6))  # s apart and sd; lognormal bytes, which vary with what happened

Write = tuple[float, int]


def acr_writes(rng: random.Random, miss: float = 0.0) -> list[Write]:
    """An hour of fingerprints inside one connection: BURST_PAYLOAD bytes every BURST_EVERY seconds, both
    drawn normal, of which a share `miss` is never sent."""
    out, t = [], rng.uniform(0, BURST_EVERY[0])
    while t < 3600:
        if rng.random() >= miss:
            out.append((t, max(BURST_FLOOR, round(rng.gauss(*BURST_PAYLOAD)))))
        t += rng.gauss(*BURST_EVERY)
    return out


def app_writes(rng: random.Random) -> list[list[Write]]:
    """An hour of an app's own interface host, on three connections: a heartbeat, a player's requests,
    and telemetry posted at random moments in sizes that vary widely, many of them large."""
    beats, requests, posts = [], [], []
    every, sd, size = APP_HEARTBEAT
    t = 0.0
    while t < 3600:
        beats.append((t, rng.randint(*size)))
        t += rng.gauss(every, sd)
    steps, sd, size = APP_REQUESTS
    t = 0.0
    while t < 3600:
        requests.append((t, rng.randint(*size)))
        t += rng.choice(steps) + rng.gauss(0, sd)
    mean, (mu, sigma), cap = APP_TELEMETRY
    t = rng.expovariate(1 / mean)
    while t < 3600:
        posts.append((t, max(1, int(min(cap, rng.lognormvariate(mu, sigma))))))
        t += rng.expovariate(1 / mean)
    return [beats, requests, posts]


def sdk_writes(rng: random.Random) -> list[Write]:
    """An hour of an analytics library's batches, one every SDK_FLUSH seconds, of lognormal size."""
    every, sd, (mu, sigma) = SDK_FLUSH
    out, t = [], rng.uniform(0, every)
    while t < 3600:
        out.append((t, max(1, int(rng.lognormvariate(mu, sigma)))))
        t += rng.gauss(every, sd)
    return out


def tap_hour(rng: random.Random, connections: list[list[Write]], shuffled: bool = False) -> list[Packet]:
    """The connections' writes as the capture holds them, in the order it took them: each write cut into
    MSS segments SEGMENT_GAP apart, PSH on its last, the sequence running on from a random first number
    (so some connections wrap). With `shuffled` each segment's moment is drawn apart from its write's
    start, as the proof of concept's first generator did, so a write's PSH segment may come before its
    fellows. The TV's ports are 40000 and up, one a connection."""
    out = []
    for sport, writes in enumerate(connections, 40_000):
        flow, seq = (sport, TAP_SERVER, 443), rng.getrandbits(32)
        for t, size in writes:
            moment = t
            for off in range(0, size, MSS):
                n = min(MSS, size - off)
                out.append(Packet(moment, flow, (seq + off) % SEQ_SPAN, n, off + n == size))
                moment = (t if shuffled else moment) + rng.uniform(*SEGMENT_GAP)
            seq = (seq + size) % SEQ_SPAN
    return sorted(out, key=lambda p: p.t)


def tap_flow(writes: list[Write], hour: float, sport: int) -> Flow:
    """The fingerprint connection of `acr_writes` as conntrack totals it at its end, the server answering
    as much as it gets: all the upload test reads of it."""
    sizes = [n for _, n in writes]
    return connection(hour, 3590.0, TAP_SERVER, 443, sport, sizes, sizes, TAP_NAME)


def insert(conn: sqlite3.Connection, flows: list[Flow], dns: list[tuple] = ()) -> None:
    """Write flows (with the hello that names each named one, sent as the connection opened) and dns rows
    (t, qname, qtype, answers, blocked) into a store."""
    conn.executemany(
        "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,pkts_up,bytes_up,pkts_down,bytes_down)"
        " VALUES (?,?,'tcp',?,?,?,?,?,?,?)",
        [
            (f.t_start, f.t_end, f.dst, f.dport, f.sport, f.pkts_up, f.bytes_up, f.pkts_down, f.bytes_down)
            for f in flows
        ],
    )
    conn.executemany(
        "INSERT INTO tls(t,dst,dport,sport,sni) VALUES (?,?,?,?,?)",
        [(f.t_start, f.dst, f.dport, f.sport, f.sni) for f in flows if f.sni],
    )
    conn.executemany("INSERT INTO dns(t,qname,qtype,answers,blocked) VALUES (?,?,?,?,?)", list(dns))
    conn.commit()
