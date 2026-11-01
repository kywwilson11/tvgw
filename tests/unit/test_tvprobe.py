"""(ledger) `tvgw tvprobe` against a fake SSAP server on localhost: the session rules (read-only, no
registration retry after a pairing error, at least 5 s between attempts, a 1 MiB frame cap, a stop
after N hours) and the consent record of the hourly reading. No TV and no network: plain WebSocket on
127.0.0.1, the server written here from RFC 6455."""

import asyncio
import base64
import hashlib
import json
import struct
import sys
import time
from types import SimpleNamespace

import pytest

from tvgw import lgwebos
from tvgw.lgwebos import ProbeConfig, ProbeLog


class FakeTv:
    """One SSAP endpoint. `script(conn)` drives each connection after the handshake; the server
    records every text message the probe sends and every close code."""

    def __init__(self, script):
        self.script = script
        self.connections = 0
        self.received: list[dict] = []
        self.closes: list[int] = []
        self.pongs = 0
        self.server = None

    async def start(self) -> int:
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def handle(self, reader, writer):
        self.connections += 1
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            key = next(
                ln.split(":", 1)[1].strip()
                for ln in head.decode().split("\r\n")
                if ln.lower().startswith("sec-websocket-key")
            )
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            writer.write(
                f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode()
            )
            await writer.drain()
            await self.script(Conn(self, reader, writer))
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


class Conn:
    def __init__(self, tv, reader, writer):
        self.tv, self.reader, self.writer = tv, reader, writer

    async def send(self, obj) -> None:
        data = json.dumps(obj).encode()
        n = len(data)
        head = bytes([0x81]) + (bytes([n]) if n < 126 else bytes([126]) + struct.pack("!H", n))
        self.writer.write(head + data)
        await self.writer.drain()

    async def recv(self) -> dict | None:
        """The next text message from the probe; pings answered, a close recorded (None)."""
        while True:
            b0, b1 = await self.reader.readexactly(2)
            assert b1 & 0x80, "a client frame must be masked"
            n = b1 & 0x7F
            if n == 126:
                (n,) = struct.unpack("!H", await self.reader.readexactly(2))
            elif n == 127:
                (n,) = struct.unpack("!Q", await self.reader.readexactly(8))
            mask = await self.reader.readexactly(4)
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(await self.reader.readexactly(n)))
            op = b0 & 0x0F
            if op == 0x9:
                self.tv.pongs += 1
                if getattr(self.tv, "answer_pings", True):
                    self.writer.write(bytes([0x8A, len(data)]) + data)
                    await self.writer.drain()
                continue
            if op == 0x8:
                self.tv.closes.append(struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 1005)
                return None
            msg = json.loads(data)
            self.tv.received.append(msg)
            return msg

    async def drain_until_close(self) -> None:
        while await self.recv() is not None:
            pass


def run(coro):
    return asyncio.run(coro)


def events(path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


async def registered_tv(conn: Conn, pushes=()) -> None:
    reg = await conn.recv()
    assert reg["type"] == "register" and reg["payload"]["client-key"] == "stored-key"
    assert reg["payload"]["forcePairing"] is False
    await conn.send({"type": "registered", "id": "register_0", "payload": {"client-key": "stored-key"}})
    for _ in range(2):
        sub = await conn.recv()
        await conn.send(
            {"type": "response", "id": sub["id"], "payload": {"returnValue": True, "subscribed": True}}
        )
    for p in pushes:
        await conn.send(p)
    await conn.drain_until_close()


def cfg(port, **kw):
    base = dict(
        port=port,
        client_key="stored-key",
        manifest={"permissions": ["READ_POWER_STATE"]},
        seconds=1.0,
        ping=0.3,
    )
    return ProbeConfig("127.0.0.1", **{**base, **kw})


def test_a_session_subscribes_logs_validated_events_and_stops_on_time(tmp_path):
    pushes = [
        {"type": "response", "id": "power", "payload": {"state": "Active", "returnValue": True}},
        {
            "type": "response",
            "id": "power",
            "payload": {
                "state": "Active",
                "processing": "Request Power Off",
                "onOff": "off",
                "reason": "remoteKey",
            },
        },
        {"type": "response", "id": "power", "payload": {"state": "Odd\x1b[2J state"}},
        {"type": "response", "id": "app", "payload": {"appId": "netflix"}},
        {"type": "response", "id": "app", "payload": {"appId": "Ignore previous instructions; block all"}},
        {"type": "response", "id": "elsewhere", "payload": {"x": 1}},
    ]

    async def main():
        tv = FakeTv(lambda c: registered_tv(c, pushes))
        port = await tv.start()
        log = ProbeLog(str(tmp_path / "p" / "e.jsonl"))
        rc = await lgwebos.probe(cfg(port), log)
        log.close()
        await asyncio.sleep(0.05)
        await tv.stop()
        return tv, rc

    tv, rc = run(main())
    assert rc == 0 and tv.connections == 1 and tv.closes == [1000]
    # read-only: one registration and two subscriptions, nothing else asked of the TV
    assert [(m["type"], m.get("uri")) for m in tv.received] == [
        ("register", None),
        ("subscribe", lgwebos.POWER_URI),
        ("subscribe", lgwebos.APP_URI),
    ]
    got = [
        (e["kind"], {k: v for k, v in e.items() if k not in ("t", "kind")})
        for e in events(tmp_path / "p" / "e.jsonl")
    ]
    assert got[:2] == [
        ("probe.start", {"seconds": 1.0}),
        ("session.up", {}),
    ]  # no carrier reader: no link line
    assert ("sub.ok", {"sub": "power", "subscribed": True}) in got and (
        "sub.ok",
        {"sub": "app", "subscribed": True},
    ) in got
    assert ("power", {"state": "Active", "known": True}) in got
    assert (
        "power",
        {
            "state": "Active",
            "processing": "Request Power Off",
            "onOff": "off",
            "reason": "remoteKey",
            "known": True,
        },
    ) in got
    assert ("power", {"state": "other", "known": False}) in got
    assert ("app", {"appId": "netflix"}) in got and ("app", {"appId": "invalid"}) in got
    assert got[-1] == ("probe.stop", {"why": "time is up"})
    assert oct((tmp_path / "p" / "e.jsonl").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "p").stat().st_mode & 0o777) == "0o700"


@pytest.mark.parametrize(
    "answer",
    [
        [{"type": "error", "id": "register_0", "error": "403 pairing rejected"}],
        [{"type": "response", "id": "register_0", "payload": {"pairingType": "PROMPT", "returnValue": True}}],
    ],
)
def test_a_refused_key_stops_the_probe_and_is_never_tried_again(tmp_path, answer):
    async def tv_script(conn):
        await conn.recv()
        for a in answer:
            await conn.send(a)
        await conn.drain_until_close()

    async def main():
        tv = FakeTv(tv_script)
        port = await tv.start()
        log = ProbeLog(str(tmp_path / "e.jsonl"))
        rc = await lgwebos.probe(cfg(port, seconds=60.0, register_grace=0.2), log)
        log.close()
        await tv.stop()
        return tv, rc

    tv, rc = run(main())
    assert rc == 2 and tv.connections == 1  # sixty seconds left, and still one attempt
    kinds = [e["kind"] for e in events(tmp_path / "e.jsonl")]
    assert kinds[-2:] == ["pair.rejected", "probe.stop"] and "session.up" not in kinds


PROMPT = {"type": "response", "id": "register_0", "payload": {"pairingType": "PROMPT", "returnValue": True}}


async def prompt_then_hang_up(conn):
    await conn.recv()
    await conn.send(PROMPT)  # the prompt is on the screen; then the socket closes, no close frame


async def prompt_then_close_frame(conn):
    await conn.recv()
    await conn.send(PROMPT)
    conn.writer.write(bytes([0x88, 2]) + struct.pack("!H", 1000))
    await conn.writer.drain()
    await conn.drain_until_close()


async def prompt_then_garbage(conn):
    await conn.recv()
    await conn.send(PROMPT)
    conn.writer.write(bytes([0x81, 8]) + b"not json")
    await conn.writer.drain()
    await conn.drain_until_close()


async def prompt_then_a_list(conn):
    await conn.recv()
    await conn.send(PROMPT)
    await conn.send([1, 2])
    await conn.drain_until_close()


async def a_list_for_an_answer(conn):
    await conn.recv()
    await conn.send(["registered"])
    await conn.drain_until_close()


@pytest.mark.parametrize(
    "script", [prompt_then_hang_up, prompt_then_close_frame, prompt_then_garbage, prompt_then_a_list, a_list_for_an_answer]
)  # fmt: skip
def test_after_a_pairing_prompt_no_ending_of_the_session_leads_to_a_second_registration(tmp_path, script):
    """However the TV ends the session once it has put a prompt up (or answers with something that is
    not an object), the probe stops with 2: a reconnect would register again and prompt again."""

    async def main():
        tv = FakeTv(script)
        port = await tv.start()
        log = ProbeLog(str(tmp_path / "e.jsonl"))
        # a long grace: the TV's hang-up, not the grace running out, is what ends the wait
        rc = await lgwebos.probe(cfg(port, seconds=60.0, register_grace=30.0), log)
        log.close()
        await tv.stop()
        return tv, rc

    tv, rc = run(main())
    assert rc == 2 and tv.connections == 1
    kinds = [e["kind"] for e in events(tmp_path / "e.jsonl")]
    assert kinds[-2:] == ["pair.rejected", "probe.stop"] and "session.fail" not in kinds
    assert sum(1 for m in tv.received if m.get("type") == "register") == 1


def test_a_handshake_reply_over_the_limit_is_a_session_failure_not_a_crash(tmp_path):
    async def handle(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 101 Switching Protocols\r\nX-Pad: " + b"a" * (1 << 17))
        await writer.drain()
        writer.close()

    async def main():
        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        log = ProbeLog(str(tmp_path / "e.jsonl"))
        rc = await lgwebos.probe(cfg(port, seconds=0.5, min_reconnect=5.0), log)
        log.close()
        server.close()
        await server.wait_closed()
        return rc

    assert run(main()) == 0
    fails = [e for e in events(tmp_path / "e.jsonl") if e["kind"] == "session.fail"]
    assert fails and "handshake reply too large or cut" in fails[0]["error"]


def test_a_frame_over_the_cap_closes_with_1009_before_its_payload_is_read(tmp_path):
    async def tv_script(conn):
        await conn.recv()
        await conn.send({"type": "registered", "id": "register_0", "payload": {}})
        conn.writer.write(bytes([0x81, 127]) + struct.pack("!Q", 2 << 20))  # 2 MiB announced, none sent
        await conn.writer.drain()
        while await conn.recv() is not None:
            pass

    async def main():
        tv = FakeTv(tv_script)
        port = await tv.start()
        log = ProbeLog(str(tmp_path / "e.jsonl"))
        rc = await lgwebos.probe(cfg(port, seconds=0.6, min_reconnect=5.0), log)
        log.close()
        await tv.stop()
        return tv, rc

    tv, rc = run(main())
    assert rc == 0 and 1009 in tv.closes
    fails = [e for e in events(tmp_path / "e.jsonl") if e["kind"] == "session.fail"]
    assert fails and "FrameTooBig" in fails[0]["error"] and str(1 << 20) in fails[0]["error"]


def test_reconnects_back_off_and_never_come_faster_than_five_seconds(tmp_path):
    """The TV accepts and hangs up at once, again and again. With a fake clock the waits are the
    schedule itself: 5, 15, 30, then 60 s, each at least 5 s after the attempt before began."""
    clock = HybridClock()
    waits = []

    async def sleep(d):
        waits.append(round(d, 1))
        await clock.sleep(d)

    async def hang_up(conn):
        conn.writer.close()

    async def main():
        tv = FakeTv(hang_up)
        port = await tv.start()
        log = ProbeLog(str(tmp_path / "e.jsonl"), clock=clock)
        rc = await lgwebos.probe(cfg(port, seconds=200.0), log, clock=clock, sleep=sleep)
        log.close()
        await tv.stop()
        return tv, rc

    tv, rc = run(main())
    assert rc == 0 and waits[:5] == [5.0, 15.0, 30.0, 60.0, 60.0] and tv.connections == 6
    assert all(w >= 5 for w in waits[:-1]) and waits[-1] <= 30.0  # the last wait is cut to the deadline


class HybridClock:
    """Fake waits on top of real time: the probe's sleeps jump the clock, while a session that holds
    still passes real time, so a session's own deadline arrives."""

    def __init__(self):
        self.offset, self.start = 0.0, time.monotonic()

    def __call__(self) -> float:
        return self.offset + time.monotonic() - self.start

    async def sleep(self, d):
        self.offset += d
        await asyncio.sleep(0)


def test_nothing_is_tried_while_the_tv_port_has_no_carrier_and_the_edges_are_logged(tmp_path):
    clock = HybridClock()
    up = iter([False, False, False, True] + [True] * 100)

    async def main():
        tv = FakeTv(lambda c: registered_tv(c))
        port = await tv.start()
        log = ProbeLog(str(tmp_path / "e.jsonl"), clock=clock)
        rc = await lgwebos.probe(
            cfg(port, seconds=3.5), log, carrier_up=lambda: next(up), clock=clock, sleep=clock.sleep
        )
        log.close()
        await tv.stop()
        return tv, rc

    tv, rc = run(main())
    links = [(round(e["t"]), e["up"]) for e in events(tmp_path / "e.jsonl") if e["kind"] == "link"]
    assert rc == 0 and links == [(0, False), (3, True)] and tv.connections == 1


def test_a_tv_that_stops_answering_pings_ends_the_session(tmp_path):
    async def silent(conn):
        conn.tv.answer_pings = False
        await registered_tv(conn)

    async def main():
        tv = FakeTv(silent)
        port = await tv.start()
        log = ProbeLog(str(tmp_path / "e.jsonl"))
        rc = await lgwebos.probe(cfg(port, seconds=1.2, ping=0.2, pong_timeout=0.2, min_reconnect=5.0), log)
        log.close()
        await tv.stop()
        return tv, rc

    tv, rc = run(main())
    fails = [e for e in events(tmp_path / "e.jsonl") if e["kind"] == "session.fail"]
    assert rc == 0 and tv.pongs >= 1 and fails and "no pong within" in fails[0]["error"]


def test_a_refused_subscription_is_logged_and_the_other_kept(tmp_path):
    async def partial(conn):
        await conn.recv()
        await conn.send({"type": "registered", "id": "register_0", "payload": {}})
        power = await conn.recv()
        await conn.send({"type": "error", "id": power["id"], "error": "404 no such service or method"})
        app = await conn.recv()
        await conn.send(
            {
                "type": "response",
                "id": app["id"],
                "payload": {"subscribed": True, "appId": "com.webos.app.home"},
            }
        )
        await conn.drain_until_close()

    async def main():
        tv = FakeTv(partial)
        port = await tv.start()
        log = ProbeLog(str(tmp_path / "e.jsonl"))
        await lgwebos.probe(cfg(port, seconds=0.5), log)
        log.close()
        await tv.stop()

    run(main())
    got = [(e["kind"], e.get("sub"), e.get("error"), e.get("appId")) for e in events(tmp_path / "e.jsonl")]
    assert ("sub.err", "power", "404 no such service or method", None) in got
    assert ("app", None, None, "com.webos.app.home") in got


def test_probe_main_refuses_to_start_without_a_pairing(tmp_path, capsys):
    assert (
        lgwebos.probe_main("10.10.10.17", str(tmp_path / "none.sqlite"), str(tmp_path / "e"), 1, "eth0") == 1
    )
    assert "the probe never pairs" in capsys.readouterr().out


def test_cli_tvprobe_checks_its_hours(tmp_path, capsys, monkeypatch):
    from tvgw import cli

    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'STATE_DIR="{tmp_path}"\n', encoding="utf-8")
    assert cli.main(["--conf", str(conf), "tvprobe", "--hours", "49"]) == 2
    seen = {}
    monkeypatch.setattr(lgwebos, "probe_main", lambda *a: seen.setdefault("args", a) and 0)
    assert cli.main(["--conf", str(conf), "tvprobe", "--hours", "26"]) == 0
    assert seen["args"][2:] == (str(tmp_path / "probe" / "tvprobe.jsonl"), 26.0, "eth0")


# ---- the consent record in the hourly reading ----------------------------------------------------------------
def test_the_consent_record_is_flattened_and_a_missing_flag_is_unknown():
    got = lgwebos.consent(
        {
            "eulaStatus": {
                "acrAllowed": False,
                "networkAllowed": True,
                "voiceAllowed": "true",
                "newThingAllowed": False,
                "bad key!": True,
            }
        }
    )
    assert got["eula.acrAllowed"] == "false" and got["eula.networkAllowed"] == "true"
    assert got["eula.voiceAllowed"] == "true" and got["eula.newThingAllowed"] == "false"
    assert got["eula.customAdAllowed"] == "unknown" and "eula.bad key!" not in got
    assert set(lgwebos.consent({}).values()) == {"unknown"} and len(lgwebos.consent({})) == len(
        lgwebos.CONSENT_FLAGS
    )
    assert set(lgwebos.consent({"eulaStatus": "garbage"}).values()) == {"unknown"}


def test_the_hourly_reading_asks_for_the_consent_record_and_ble_advertising(monkeypatch):
    asked = []

    class Tv:
        @classmethod
        async def create(cls, ip, states, key_file_path):
            return cls()

        async def connect(self):
            pass

        async def get_system_settings(self, cat, keys):
            asked.append((cat, keys[0]))
            if keys[0] == "eulaStatus":
                return {"settings": {"eulaStatus": {"acrAllowed": False}}}
            if keys[0] == "bleAdvertisingOnOff":
                return {"settings": {}}  # the TV left it out
            return {"settings": {keys[0]: "off"}}

        async def request(self, uri):
            return {}

        async def get_software_info(self):
            return {}

        async def get_system_info(self):
            return {}

        async def get_power_state(self):
            return {"state": "Active"}

        async def get_current_app(self):
            return "netflix"

        async def disconnect(self):
            pass

    monkeypatch.setitem(sys.modules, "bscpylgtv", SimpleNamespace(WebOsClient=Tv))
    r = lgwebos.read("10.10.10.17", "/nonexistent", timeout=0.5)
    assert ("", "eulaStatus") in asked and ("network", "bleAdvertisingOnOff") in asked
    assert asked[-1] == ("", "eulaStatus")  # the unverified call comes last
    assert r.values["network.bleAdvertisingOnOff"] == "unknown"
    assert r.values["eula.acrAllowed"] == "false" and r.values["eula.voiceAllowed"] == "unknown"
    assert r.exit_code() == 0  # neither is a warning in the hourly job

    # a TV that stalls on the consent record loses those keys only: power, app and the paths stand
    async def stall(self, cat, keys):
        if keys[0] == "eulaStatus":
            await asyncio.sleep(60)
        return {"settings": {keys[0]: "off"}}

    async def paths(self, uri):
        return {"wired": {"state": "connected"}}

    monkeypatch.setattr(Tv, "get_system_settings", stall)
    monkeypatch.setattr(Tv, "request", paths)
    monkeypatch.setattr(lgwebos, "CONSENT_TIMEOUT", 0.2)
    r = lgwebos.read("10.10.10.17", "/nonexistent", timeout=0.5)
    assert (r.values["power"], r.values["app"]) == ("Active", "netflix")
    assert r.values["network.wired.state"] == "connected"
    assert r.values["eula.status"].startswith("ERR TimeoutError")


def test_a_consent_flag_turning_on_is_a_red_line_and_ble_never_is(tmp_path, lg):
    from tvgw import db, queries

    conn = db.connect(str(tmp_path / "s.db"))
    day = 1792990800
    conn.executemany(
        "INSERT INTO tvsettings(t, key, value) VALUES (?, ?, ?)",
        [
            (day - 86400, "eula.acrAllowed", "false"),
            (day + 3600, "eula.acrAllowed", "true"),  # a flip: red
            (day - 86400, "eula.generalTermsAllowed", "true"),  # true from the first reading: not a flip
            (day - 86400, "eula.voiceAllowed", "unknown"),
            (day + 7200, "eula.voiceAllowed", "true"),  # unknown before: not known to have flipped
            (day - 86400, "eula.personalAdAllowed", "false"),
            (day + 1800, "eula.personalAdAllowed", "unknown"),  # one partial answer in between
            (day + 5400, "eula.personalAdAllowed", "true"),  # still a flip from the last definite false
            (day - 86400, "eula.aiRecommendAllowed", "true"),
            (day + 1800, "eula.aiRecommendAllowed", "unknown"),
            (day + 5400, "eula.aiRecommendAllowed", "true"),  # true, unknown, true: no flip
            (day - 86400, "network.bleAdvertisingOnOff", "off"),
            (day + 3600, "network.bleAdvertisingOnOff", "on"),
        ],
    )
    conn.commit()
    o = queries.brief(conn, "2026-10-26", lg, now=day + 86400)
    assert o["consent_flips"] == [
        {"t": day + 3600, "flag": "acrAllowed"},
        {"t": day + 5400, "flag": "personalAdAllowed"},
    ]
    assert [r for r in o["red_lines"] if "consent" in r or "ble" in r.lower()] == [
        "TV consent flag acrAllowed turned on (at 2026-10-26 01:00): an agreement was accepted on the TV",
        "TV consent flag personalAdAllowed turned on (at 2026-10-26 01:30): an agreement was accepted on the TV",
    ]
