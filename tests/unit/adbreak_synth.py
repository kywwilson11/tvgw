"""(adbreaks) A stand-in evening of streaming with ad breaks, as the refused lookups it leaves (design
decision 89). Not a test file. Seeded, standard library only, no clock.

An ad follows the VAST events a player reports (the impression at its start, then start, the quartiles
and the end), to the app's own two ad hosts (one firm) and to two to five of sixty measurement firms,
each of which follows every event about one time in three and the impression alone otherwise. Spots are 15 and 30 seconds for the most
part, two to six to a break, a break every 8 to 14 minutes, and half of the episode starts play one or
two ads first. Around the ads the log holds what a TV's log holds: the ad request every episode makes, the
analytics names an app asks when it starts and when it flushes, and names asked on a timer, half of
them advertising firms' own.

A request makes a lookup only when the TV has not asked that name in the last `hold` seconds: a TV keeps
a refusal for a while (the reference's keeps it 60 seconds).

What the rule finds here rests on the app's own ad server being a firm the filter refuses: it is one of
the three firms an ad needs wherever the ad calls only two others.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

SESSION = 7200.0  # seconds of one evening, from the top of a clock hour
SPOTS = ((15, 0.50), (30, 0.40), (6, 0.05), (60, 0.05))  # an ad's seconds, and how common
POD_ADS, PREROLL_ADS = (2, 6), (1, 2)
BREAK_EVERY = (480.0, 840.0)  # seconds of show between breaks
EPISODE = (1320.0, 2880.0)  # seconds between episode starts
P_PREROLL = 0.5
VENDORS, AD_VENDORS, P_QUARTILES = 60, (2, 5), 0.35
APP_AD_HOSTS = ("ads.appads0.test", "beacon.appads1.test")
FAST_TIMERS, SLOW_TIMERS = 16, 3  # periods of 45 to 350 seconds, and of 380 to 700
SDKS, LAUNCH_SDKS, FLUSH_PER_HOUR = 12, (4, 8), 2.0


def vendor(v: int) -> str:
    return f"px.vendor{v}.test"


def timer(i: int) -> str:
    """Every other fast timer is an advertising firm's name."""
    return f"beat.{'adtimer' if i < FAST_TIMERS and i % 2 == 0 else 'timer'}{i}.test"


# what companies.ADFIRMS would hold of these names: domain -> company
FIRMS = {
    **{f"vendor{v}.test": f"Vendor {v}" for v in range(VENDORS)},
    **{host.partition(".")[2]: "The app's ad server" for host in APP_AD_HOSTS},
    **{f"adtimer{i}.test": f"Timer {i}" for i in range(0, FAST_TIMERS, 2)},
}


@dataclass(frozen=True)
class Shown:
    """A break as it was shown: when, and whether the TV itself called the firms (else the service's
    servers did, and the log holds nothing of it)."""

    start: float
    end: float
    called: bool


def _spot(rng: random.Random) -> int:
    return rng.choices([seconds for seconds, _p in SPOTS], [p for _seconds, p in SPOTS])[0]


def evening(
    rng: random.Random, t0: float, hold: float = 60.0, called: float = 1.0
) -> tuple[list[tuple[float, str]], list[Shown]]:
    """(the refused lookups of one evening that begins at `t0`, in time order; its breaks). `called` is
    the share of breaks whose firms the TV itself calls."""
    episodes = [0.0]
    while episodes[-1] + EPISODE[0] < SESSION:
        episodes.append(episodes[-1] + rng.uniform(*EPISODE))
    episodes = [e for e in episodes if e < SESSION - 120]
    starts = sorted((e, True) for e in episodes if rng.random() < P_PREROLL)
    t = rng.uniform(120.0, BREAK_EVERY[1])
    while t < SESSION - 240:
        starts.append((t, False))
        t += rng.uniform(*BREAK_EVERY) + 120.0
    asked: list[tuple[float, str]] = []
    shown: list[Shown] = []
    weights = [1.0 / (v + 1) for v in range(VENDORS)]
    for at, preroll in sorted(starts):
        if shown and at < shown[-1].end + 90:
            continue
        is_called, u = rng.random() < called, at
        for _ in range(rng.randint(*(PREROLL_ADS if preroll else POD_ADS))):
            seconds = _spot(rng)
            events = [0.0, 0.2, seconds / 4, seconds / 2, 3 * seconds / 4, seconds - 0.2]
            if is_called:
                asked += [(u + e + rng.uniform(0, 0.4), host) for host in APP_AD_HOSTS for e in events]
                for v in set(rng.choices(range(VENDORS), weights, k=rng.randint(*AD_VENDORS))):
                    follows = events if rng.random() < P_QUARTILES else events[:1]
                    asked += [(u + e + rng.uniform(0, 0.6), vendor(v)) for e in follows]
            u += seconds
        shown.append(Shown(at, u, is_called))
    for e in episodes:  # the ad request at a video's start, ad or no ad
        asked += [(e + rng.uniform(0, 1.5), host) for host in APP_AD_HOSTS]
    asked += [(rng.uniform(0, 3.0), f"sdk{i}.test") for i in range(rng.randint(*LAUNCH_SDKS))]
    t = rng.expovariate(FLUSH_PER_HOUR / 3600.0)
    while t < SESSION:
        asked += [
            (t + rng.uniform(0, 5.0), f"sdk{i}.test") for i in rng.sample(range(SDKS), rng.randint(2, 4))
        ]
        t += rng.expovariate(FLUSH_PER_HOUR / 3600.0)
    for i in range(FAST_TIMERS + SLOW_TIMERS):
        period = rng.uniform(45.0, 350.0) if i < FAST_TIMERS else rng.uniform(380.0, 700.0)
        t = rng.uniform(0, period)
        while t < SESSION:
            asked.append((max(0.0, t + rng.gauss(0, 1.0)), timer(i)))
            t += period
    last: dict[str, float] = {}
    refused = []
    for t, name in sorted(asked):
        if name not in last or t - last[name] >= hold:
            last[name] = t
            refused.append((t0 + t, name))
    return refused, [Shown(t0 + s.start, t0 + s.end, s.called) for s in shown]
