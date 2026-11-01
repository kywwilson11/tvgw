"""(ledger) A synthetic store for the change ledger, the hour classifier and judge v2: hours of
streaming, hours on an input, hours off, changes and gateway samples, each one call. Addresses are
documentation ranges; the names are placeholders."""

from __future__ import annotations

import dataclasses

from tvgw import db, ledger

H0 = 1792990800  # 2026-10-26 00:00 CDT, hour-aligned: the synthetic day starts here
HOUR = 3600
CDN = "cdn.example"  # a Streaming name in the hosts table
APP = "netflix"
HDMI = "com.webos.app.hdmi1"


class Synth:
    """Writes into a fresh store; every method commits."""

    def __init__(self, path: str):
        self.path = path
        self.conn = db.connect(path)
        self.conn.execute(
            "INSERT OR REPLACE INTO hosts(name, category, first_seen, last_seen) VALUES (?, 'Streaming', 0, 0)",
            (CDN,),
        )
        self.sport = 40000
        self.conn.commit()

    def stream(self, h: int, mbytes: float = 40.0, app: str = APP, starts: int = 4, lookups: int = 3) -> None:
        """An hour of streaming: a reading with the app in front, `starts` connections to the CDN that
        open and close inside the hour carrying `mbytes` between them, and `lookups` of its name."""
        self.reading(h, "Active", app)
        for i in range(starts):
            self.sport += 1
            t0 = h + 300 + i * 600
            self.conn.execute(
                "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (?, '203.0.113.9', 443, ?, ?)",
                (t0, self.sport, CDN),
            )
            self.conn.execute(
                "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_up, bytes_down, state)"
                " VALUES (?, ?, 'tcp', '203.0.113.9', 443, ?, 1000, ?, 'TIME_WAIT')",
                (t0, t0 + 400, self.sport, int(mbytes * 1e6 / max(starts, 1))),
            )
        for i in range(lookups):
            self.conn.execute(
                "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, ?, 'A', 'A:203.0.113.9', 0)",
                (h + 200 + i * 60, CDN),
            )
        self.conn.commit()

    def flow(self, t0: float, t1: float, mbytes: float) -> None:
        """One CDN connection from t0 to t1 (for the proration tests)."""
        self.sport += 1
        self.conn.execute(
            "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (?, '203.0.113.9', 443, ?, ?)",
            (t0, self.sport, CDN),
        )
        self.conn.execute(
            "INSERT INTO flows(t_start, t_end, proto, dst, dport, sport, bytes_down) VALUES (?, ?, 'tcp',"
            " '203.0.113.9', 443, ?, ?)",
            (t0, t1, self.sport, int(mbytes * 1e6)),
        )
        self.conn.commit()

    def reading(self, h: int, power: str = "Active", app: str | None = APP) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO tvstate(t, power, app) VALUES (?, ?, ?)", (h + 1200, power, app)
        )
        self.conn.commit()

    def change(self, t: float, kind: str, subject: str = "x", source: str = "sampler", **kw) -> None:
        ledger.write(self.conn, [ledger.Change(t, source, kind, subject, **kw)])
        self.conn.commit()

    def sample(self, t: float, **fields) -> None:
        base = {"boot_id": "0" * 8 + "-0000-0000-0000-" + "0" * 12, "ct_count": 100, "ct_max": 262144}
        ledger.record_sample(self.conn, dataclasses.replace(ledger.Sample(t), **{**base, **fields}))

    def close(self) -> None:
        self.conn.close()
