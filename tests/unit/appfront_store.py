"""(app in front) A synthetic store and live record for the session, picture and evaluation tests:
readings, connections with their hellos, lookups, and events as the live reading or a `tvgw tvprobe` log
writes them. Addresses are documentation ranges; the times start at a fixed local midnight."""

from __future__ import annotations

import json

from tvgw import db
from tvgw.appfront import Event

H0 = 1792990800.0  # 2026-10-26 00:00 CDT
HOUR, DAY = 3600.0, 86400.0
YT, NF, PV = "youtube.leanback.v4", "netflix", "amazon"
HOME, HDMI, LIVETV, CAST = "com.webos.app.home", "com.webos.app.hdmi1", "com.webos.app.livetv", "airplay"
GW = "10.10.10.1"


def evening(day: int, hour: float = 20.0) -> float:
    """`hour` o'clock on the store's day number `day`."""
    return H0 + day * DAY + hour * HOUR


def up(t: float) -> Event:
    return Event(t, "conn", "up")


def down(t: float, why: str = "lost") -> Event:
    return Event(t, "conn", "down", why)


def app(t: float, app_id: str) -> Event:
    return Event(t, "app", app_id)


def power(t: float, state: str, processing: str = "") -> Event:
    return Event(t, "power", state, processing)


def clock(t: float, step: float) -> Event:
    return Event(t, "clock", repr(float(step)))


def watched(t0: float, t1: float, *changes: tuple[float, str]) -> list[Event]:
    """One session to the TV from t0 to t1, the TV on, with the app changes given as (t, app); the first
    is what was already in front."""
    return [up(t0), power(t0, "Active"), *[app(t, a) for t, a in changes], down(t1)]


class Store:
    """Writes into a fresh store; every method commits."""

    def __init__(self, path: str):
        self.path = str(path)
        self.conn = db.connect(self.path)
        self.sport = 40000

    def reading(self, t: float, power_: str, app_: str | None = None) -> None:
        self.conn.execute("INSERT OR REPLACE INTO tvstate(t, power, app) VALUES (?,?,?)", (t, power_, app_))
        self.conn.commit()

    def talk(
        self,
        t: float,
        name: str | None,
        up_: int = 1_000,
        down_: int = 9_000,
        dst: str = "203.0.113.10",
        ja4: str = "",
        late: float = 0.0,
        seconds: float = 60.0,
        sport: int | None = None,
    ) -> int:
        """One connection whose hello (when it has a name) went out at `t`; conntrack's start is `late`
        seconds after. Returns the source port."""
        self.sport += 1
        sport = sport or self.sport
        if name is not None:
            self.conn.execute(
                "INSERT INTO tls(t,dst,dport,sport,sni,ech,ja4,transport,partial) VALUES (?,?,?,?,?,0,?,'tcp',0)",
                (t, dst, 443, sport, name, ja4),
            )
        self.conn.execute(
            "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,pkts_up,bytes_up,pkts_down,bytes_down,state)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (t + late, t + late + seconds, "tcp", dst, 443, sport, 10, up_, 10, down_, "TIME_WAIT"),
        )
        self.conn.commit()
        return sport

    def lookup(self, t: float, qname: str, blocked: int = 0) -> None:
        self.conn.execute("INSERT INTO dns(t, qname, qtype, blocked) VALUES (?,?,'A',?)", (t, qname, blocked))
        self.conn.commit()


def probe_lines(events: list[Event]) -> str:
    """The events as a `tvgw tvprobe` log writes them (lgwebos.ProbeLog), one JSON line each."""
    out = [json.dumps({"t": events[0].t - 1, "kind": "probe.start", "seconds": 93600.0})]
    for e in events:
        if e.kind == "conn" and e.value == "up":
            rec = {"kind": "session.up"}
        elif e.kind == "conn":
            rec = {"kind": "session.fail", "error": f"{e.detail}: the session to 10.10.10.17 broke"}
        elif e.kind == "app":
            rec = {"kind": "app", "appId": e.value or None}
        elif e.kind == "power":
            rec = {"kind": "power", "state": e.value, "known": True}
            if e.detail:
                rec["processing"] = e.detail
        elif e.kind == "link":
            rec = {"kind": "link", "up": e.value == "up"}
        else:
            continue
        out.append(json.dumps({"t": e.t, **rec}))
        if rec["kind"] == "session.up":
            out.append(json.dumps({"t": e.t, "kind": "sub.ok", "sub": "power", "subscribed": True}))
    return "\n".join(out) + "\n"
