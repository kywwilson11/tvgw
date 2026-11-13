"""(screentest) A stand-in that plays the TV's part for the screen test (design decision 88), on a clock
of its own: no socket, no sleep, nothing that can run late.

`Double.step(seen)` is one second of a TV. It is told only what is on its screen in that second, as a TV
sees it, never the order the test drew, and it answers with what it sent to each of its servers:
ordinary traffic to seven of them (heartbeats, telemetry, one busy connection with a heavy tail) and, by
mode, a screen-recognition client:

- `lg`: 22.6 KB about every 14 seconds to a server of its own, when what it saw since the last upload
  was mostly the pattern (`acr_synth`'s numbers for LG's client);
- `lg-hidden`: the same uploads inside the busiest ordinary connection;
- `samsung`: 0.86 KB, and 3.3 KB half the time, about once a minute, to a server of its own;
- `sluggish`: `lg`, but it takes 20 seconds of pattern to start and goes on for 30 after it stops;
- `timer`: an upload every 14 seconds whatever is on the screen, as three vendors were measured to do.
  The test must stay silent here, which is why a "no" may not read as "no recognition";
- `none`: ordinary traffic only.
"""

from __future__ import annotations

import random

from tvgw import connpoll, screentest

MODES = ("lg", "lg-hidden", "samsung", "sluggish", "timer", "none")
SERVERS = 8  # seven ordinary ones, and one only a recognition client with a server of its own uses
BUSY, OWN = 0, SERVERS - 1
PERIOD = {"lg": 14, "lg-hidden": 14, "sluggish": 14, "timer": 14, "samsung": 60}
START, HANGOVER = 20, 30  # seconds a sluggish client takes to begin, and goes on after the pattern stops


class Double:
    def __init__(self, mode: str, rng: random.Random):
        self.mode, self.rng = mode, rng
        self.period = PERIOD.get(mode)
        self.to = BUSY if mode == "lg-hidden" else OWN
        self.seen: list[bool] = []
        self.next_upload = rng.uniform(0, self.period) if self.period else None
        self.beats = [(rng.uniform(30, 300), rng.uniform(300, 3000)) for _ in range(SERVERS - 1)]
        self.next_beat = [rng.uniform(0, every) for every, _size in self.beats]
        self.lit_for = self.dark_for = 0  # seconds the pattern has been on, and off, without a break
        self.awake = False  # a sluggish client's recognition, once it has started

    def watching(self) -> bool:
        """Whether the recognition client would report now, from what it has seen."""
        if self.mode == "timer":
            return True
        if self.mode == "sluggish":
            self.awake = self.lit_for >= START or (self.awake and self.dark_for < HANGOVER)
            return self.awake
        window = self.seen[-self.period :]
        return sum(window) * 2 >= len(window)

    def step(self, seen: bool) -> dict[int, float]:
        """One second: what is on the screen in, the bytes sent to each server out."""
        rng, t = self.rng, len(self.seen)
        self.seen.append(seen)
        self.lit_for, self.dark_for = (self.lit_for + 1, 0) if seen else (0, self.dark_for + 1)
        sent: dict[int, float] = {}

        def send(server: int, size: float) -> None:
            sent[server] = sent.get(server, 0.0) + max(0.0, size)

        for server, (every, size) in enumerate(self.beats):
            if t >= self.next_beat[server]:
                send(server, size)
                self.next_beat[server] += every
        if rng.random() < 6 / 60:  # the busy connection: six uploads a minute, a few of them large
            send(BUSY, min(400_000, 4000 * rng.lognormvariate(0, 1.2)))
        for server in range(1, SERVERS - 1):
            if rng.random() < 0.5 / 60:
                send(server, 2000 * rng.lognormvariate(0, 1.0))
        if self.next_upload is not None and t >= self.next_upload:
            if self.watching():
                if self.mode == "samsung":
                    send(self.to, rng.gauss(860, 30) + (rng.gauss(3300, 200) if rng.random() < 0.5 else 0))
                else:
                    send(self.to, rng.gauss(22_600, 500))
            self.next_upload += self.period + rng.gauss(0, 3.0 if self.mode == "samsung" else 0.1)
        return sent


def run(mode: str, on: list[bool], width: int, rng: random.Random) -> dict[str, list[float]]:
    """A whole run: the pattern played to a double, and what each server and all of them received in
    each second, as the one-second poll would give it."""
    seconds = screentest.seconds_needed(len(on), width)
    tv = Double(mode, rng)
    received = [[0.0] * seconds for _ in range(SERVERS)]
    for t in range(seconds):
        slot = t // width
        for server, size in tv.step(slot < len(on) and on[slot]).items():
            received[server][t] += size
    series = {connpoll.cell(f"198.18.{server}.1", 443): xs for server, xs in enumerate(received) if any(xs)}
    series[screentest.TOTAL] = [sum(xs[t] for xs in received) for t in range(seconds)]
    return series
