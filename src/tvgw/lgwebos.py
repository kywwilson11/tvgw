"""LG webOS LAN API (SSAP, tcp/3000): read the TV's privacy-relevant settings.

Needs the optional `bscpylgtv` dependency (`pip install tvgw[lgwebos]`) and a one-time pairing
(`bscpylgtvcommand -p <key file> <tv ip> get_software_info`, accept the prompt on the TV).
Firmware 04.64 (webOS 5) refuses writes through this API (its `isCallAllowed` guard rejects the
Luna side-door every LAN tool uses), so this module only reads.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import re
import ssl
import struct
import time
from dataclasses import dataclass, field

READS = (
    ("option", ("livePlus", "zipcode", "country", "audioGuidance", "storeMode")),
    # (ledger) bleAdvertisingOnOff: recorded only, never a red line (Bluetooth carries no data on its own)
    ("network", ("deviceName", "wolwowlOnOff", "bleAdvertisingOnOff")),
    ("other", ("simplinkEnable",)),
)
ACR_KEY = "option.livePlus"
# (ledger) keys a TV may leave out of its answer: a missing one reads `unknown`, never `off` or `None`
UNKNOWN_IF_MISSING = frozenset({"network.bleAdvertisingOnOff"})
# (ledger) the consent record: `eulaStatus` in the settings category "" holds one flag per agreement
# (the public read list of the CX dump in bscpylgtv's docs). Each is stored as `eula.<flag>` = true,
# false or unknown; a flag the TV leaves out, or a record that is not there at all, is unknown
CONSENT_CATEGORY, CONSENT_KEY = "", "eulaStatus"
CONSENT_TIMEOUT = 5.0  # seconds: the consent call's own limit, under the per-call timeout
CONSENT_FLAGS = (
    "acrAllowed", "acrOnAllowed", "acrAdAllowed", "acrGdprAllowed", "voiceAllowed", "voice2Allowed",
    "customAdAllowed", "customadsAllowed", "thirdPartySharingAllowed", "cookiesAllowed",
    "marketingOnAllowed", "remoteDiagAllowed", "chpAllowed", "takeOnAllowed", "generalTermsAllowed",
    "additionalDataAllowed", "additional1Allowed", "additional2Allowed", "additional3Allowed",
    "additional4Allowed", "additional5Allowed", "networkAllowed",
)  # fmt: skip
CONSENT_PREFIX = "eula."
_FLAG = re.compile(r"[A-Za-z][A-Za-z0-9]{0,39}")


def consent(settings) -> dict[str, str]:
    """The consent record as settings-like keys. Every known flag is present: `true` or `false` when the
    TV said so, `unknown` otherwise; a flag this list does not know is kept when its name is plain."""
    record = settings.get(CONSENT_KEY) if isinstance(settings, dict) else None
    record = record if isinstance(record, dict) else {}

    def word(v) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, str) and v.lower() in ("true", "false"):
            return v.lower()
        return "unknown"

    out = {f"{CONSENT_PREFIX}{flag}": word(record.get(flag)) for flag in CONSENT_FLAGS}
    for flag in sorted(record):
        if isinstance(flag, str) and flag not in CONSENT_FLAGS and _FLAG.fullmatch(flag):
            out[f"{CONSENT_PREFIX}{flag}"] = word(record[flag])
    return out


# The TV's network paths, read with the settings: the states of its wired port, Wi-Fi and Wi-Fi Direct,
# and whether Wi-Fi or Bluetooth tethering is on (connectionmanager/getstatus; the method name is
# lower-case on webOS 5, the CamelCase form answers 404). Anything but the wired port is traffic the
# gateway never sees, so the brief and `tvgw verify` treat it as a red line (design decision 40).
PATHS_URI = "com.webos.service.connectionmanager/getstatus"
PATH_KEYS = (
    "network.wired.state",
    "network.wifi.state",
    "network.wifiDirect.state",
    "network.wifi.tethering",
    "network.bluetooth.tethering",
)
SECOND_PATHS = {
    "network.wifi.state": "Wi-Fi",
    "network.wifiDirect.state": "Wi-Fi Direct",
    "network.wifi.tethering": "Wi-Fi tethering",
    "network.bluetooth.tethering": "Bluetooth tethering",
}


def is_second_path(key: str, value: str | None) -> bool:
    """Whether one reading of a SECOND_PATHS key says the TV can reach a network around the gateway: a
    tethering switch that is on, or a radio in any state but disconnected. Unread, unknown and a read
    error are not: verify and the brief say what they know, never what they fear."""
    if value is None or value == "unknown" or value.startswith("ERR "):
        return False
    if key.endswith(".tethering"):
        return value == "on"
    return value != "disconnected"


def paths(status) -> dict[str, str]:
    """connectionmanager/getstatus as settings-like keys. A part the TV left out reads as `unknown`,
    never as a guess."""

    def state(part: str) -> str:
        v = status.get(part) if isinstance(status, dict) else None
        return clean(v.get("state", "unknown")) if isinstance(v, dict) else "unknown"

    def tethering(part: str) -> str:
        v = status.get(part) if isinstance(status, dict) else None
        if not isinstance(v, dict) or "tetheringEnabled" not in v:
            return "unknown"
        return "on" if v["tetheringEnabled"] else "off"

    return {
        "network.wired.state": state("wired"),
        "network.wifi.state": state("wifi"),
        "network.wifiDirect.state": state("wifiDirect"),
        "network.wifi.tethering": tethering("wifi"),
        "network.bluetooth.tethering": tethering("bluetooth"),
    }


@dataclass
class TvReading:
    reachable: bool
    values: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def acr_off(self) -> bool | None:
        v = self.values.get(ACR_KEY)
        return None if v is None else v == "off"

    @property
    def second_paths(self) -> list[str]:
        """The ways the TV reports it can reach a network besides its wired port."""
        return [label for key, label in SECOND_PATHS.items() if is_second_path(key, self.values.get(key))]

    def lines(self) -> list[str]:
        if not self.reachable:
            return [f"TV unreachable ({self.error}): off, or in standby with Quick Start+ off"]
        out = [f"{k} = {v}" for k, v in self.values.items()]
        if self.acr_off is False:
            out.append("WARNING: Live Plus (ACR) is NOT off; check General > Additional Settings on the TV")
        if self.second_paths:
            out.append(
                "WARNING: the TV has a second network path ("
                + ", ".join(self.second_paths)
                + "): traffic can leave around the gateway; Settings > Network"
            )
        return out

    def exit_code(self) -> int:
        """0 fine, 1 unreachable, 2 ACR on, 3 a second network path - what the hourly job keys off."""
        if not self.reachable:
            return 1
        if self.second_paths:
            return 3
        return 2 if self.acr_off is False else 0


async def _read(ip: str, key_file: str, timeout: float, r: TvReading) -> TvReading:
    """Fill `r`, which the caller holds: when the whole reading runs out of time, what was read so far
    is still there."""
    try:
        from bscpylgtv import WebOsClient  # optional dependency
    except ImportError as e:  # pragma: no cover - depends on the install
        r.error = f"bscpylgtv not installed ({e})"
        return r
    try:
        c = await asyncio.wait_for(WebOsClient.create(ip, states=[], key_file_path=key_file), timeout)
        await asyncio.wait_for(c.connect(), timeout)
    except Exception as e:  # any failure here just means "not reachable now"
        r.error = type(e).__name__
        return r
    r.reachable, r.error = True, None
    for cat, keys in READS:
        for k in keys:
            try:
                res = await asyncio.wait_for(c.get_system_settings(cat, [k]), timeout)
                value = res.get("settings", {}).get(k)
                if value is None and f"{cat}.{k}" in UNKNOWN_IF_MISSING:  # (ledger)
                    value = "unknown"
                r.values[f"{cat}.{k}"] = clean(value)
            except Exception as e:  # a TV that stalls or refuses one key must not hide the others
                r.values[f"{cat}.{k}"] = f"ERR {type(e).__name__} {str(e)[:60]}"
    try:
        r.values.update(paths(await asyncio.wait_for(c.request(PATHS_URI), timeout)))
    except Exception as e:  # an older or stranger webOS: the rest of the reading stands
        r.values["network.paths"] = f"ERR {type(e).__name__} {str(e)[:60]}"
    try:
        sw = await asyncio.wait_for(c.get_software_info(), timeout)
        r.values["firmware"] = clean(f"{sw.get('major_ver')}.{sw.get('minor_ver')}")
        # the retail model (OLED55CXPUA) is in getSystemInfo; software info carries LG's platform code
        if sw.get("model_name"):
            r.values["platform"] = clean(sw["model_name"])
        if sw.get("country"):
            r.values["country"] = clean(sw["country"])
        try:
            info = await asyncio.wait_for(c.get_system_info(), timeout)
            if info.get("modelName"):
                r.values["model"] = clean(info["modelName"])
        except Exception as e:
            r.values["model"] = f"ERR {type(e).__name__}"
        r.values["power"] = clean((await asyncio.wait_for(c.get_power_state(), timeout)).get("state"))
        r.values["app"] = clean(await asyncio.wait_for(c.get_current_app(), timeout) or "")
    except Exception as e:
        r.values["info"] = f"ERR {type(e).__name__} {str(e)[:60]}"
    # (ledger) the consent record, flattened, last and on a shorter clock: the call is not yet verified
    # on every webOS, so a TV that stalls on it loses these keys only, never power, app or the paths.
    # A refusal leaves the flags unread, not off
    try:
        res = await asyncio.wait_for(
            c.get_system_settings(CONSENT_CATEGORY, [CONSENT_KEY]), min(timeout, CONSENT_TIMEOUT)
        )
        r.values.update(consent((res or {}).get("settings", {})))
    except Exception as e:
        r.values[f"{CONSENT_PREFIX}status"] = f"ERR {type(e).__name__} {str(e)[:60]}"
    with contextlib.suppress(Exception):  # nothing left to do with a half-closed socket
        await asyncio.wait_for(c.disconnect(), timeout)
    return r


def clean(v) -> str:
    """One line of printable text: values come from the TV (its deviceName is user-set) and end up in
    files other tools parse line by line."""
    return "".join(ch if ch.isprintable() else " " for ch in str(v))[:200]


def read(ip: str, key_file: str, timeout: float = 20.0) -> TvReading:
    """Read the TV; never hangs: each call gets `timeout`, the whole reading four times that. A TV that
    stalls on several keys runs the reading out of time; the keys read by then (Live Plus is first)
    are kept, and the ones never asked read as errors, which ingest does not store."""
    r = TvReading(False, error="TimeoutError")
    try:
        return asyncio.run(asyncio.wait_for(_read(ip, key_file, timeout, r), timeout * 4))
    except TimeoutError:
        if r.reachable:
            for cat, keys in READS:
                for k in keys:
                    r.values.setdefault(f"{cat}.{k}", "ERR TimeoutError the reading ran out of time")
        return r


# ---- (ledger) `tvgw tvprobe`: one long-lived, read-only session ---------------------------------------
# The hourly reading misses whole sessions: a 20-minute evening is seen one time in three, and when
# the readings either side say off, its traffic is booked as "while off". The probe holds one session
# over the existing pairing, subscribes to the power state and the foreground app where the firmware
# allows it, and logs every change with the Pi's receive time, so the edges and the vocabulary can be
# measured before a watcher is built on them (section 14 of the November research). It never writes
# to the TV, never subscribes to channels or programmes, never opens the pointer-input socket, never
# sends Wake-on-LAN and never pairs: a key the TV refuses ends the probe for good, because every
# registration attempt with a refused key puts a prompt on the screen.
#
# The WebSocket client is tvgw's own, about a hundred lines of RFC 6455, rather than the library the
# hourly reading uses, because that library opens its socket with no frame size limit: a TV-controlled
# peer could make the Pi buffer any amount. Here a frame or a message over PROBE_FRAME_MAX closes the
# session with 1009 before its payload is read.
PROBE_PORT = 3001  # wss: this CX refuses ws on 3000 (section 14, F2)
PROBE_FRAME_MAX = 1 << 20  # bytes in one frame or one message
PROBE_MIN_RECONNECT = 5.0  # seconds between two connection attempts, whatever happened
PROBE_BACKOFF = (5.0, 15.0, 30.0, 60.0)  # after a failure: then every 60 s
PROBE_PING = 30.0  # seconds between our pings; the library's pinger runs only while it thinks the TV is on
PROBE_PONG_TIMEOUT = 10.0
PROBE_REGISTER_GRACE = 3.0  # a stored key is answered `registered` at once; a prompt is not waited out
PROBE_IO_TIMEOUT = 15.0
POWER_URI = "ssap://com.webos.service.tvpower/power/getPowerState"
APP_URI = "ssap://com.webos.applicationManager/getForegroundAppInfo"
POWER_STATES = frozenset({"Active", "Active Standby", "Screen Off", "Screen Saver", "Suspend", "Power Off"})
POWER_FIELDS = ("state", "processing", "onOff", "reason", "powerOnReason")
_APP_ID = re.compile(r"[a-z0-9][a-z0-9._+-]{0,127}")
_POWER_WORD = re.compile(r"[A-Za-z][A-Za-z0-9 _-]{0,40}")
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class ProbeError(Exception):
    """The session failed: the probe reconnects after its backoff."""


class FrameTooBig(ProbeError):
    """The TV sent a frame or a message over PROBE_FRAME_MAX."""


class PairingRejected(Exception):
    """The TV did not accept the stored key: the probe stops and never registers again."""


class _WebSocket:
    """A client WebSocket (RFC 6455) over asyncio streams: text frames, ping and pong, close, with every
    frame's length checked against PROBE_FRAME_MAX before its payload is read."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, frame_max: int):
        self.reader, self.writer, self.frame_max = reader, writer, frame_max
        self.pongs = 0

    @classmethod
    async def connect(cls, host: str, port: int, ssl_ctx, frame_max: int = PROBE_FRAME_MAX) -> _WebSocket:

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx, limit=1 << 16), PROBE_IO_TIMEOUT
        )
        key = base64.b64encode(os.urandom(16)).decode()
        writer.write(
            (
                f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        await writer.drain()
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), PROBE_IO_TIMEOUT)
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError) as e:
            writer.close()
            raise ProbeError("handshake reply too large or cut") from e
        lines = head.decode("latin-1").split("\r\n")
        want = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode(), usedforsecurity=False).digest()
        ).decode()
        headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:] if ln)}
        if " 101 " not in lines[0] + " " or headers.get("sec-websocket-accept") != want:
            writer.close()
            raise ProbeError(f"not a WebSocket upgrade: {clean(lines[0])[:80]}")
        return cls(reader, writer, frame_max)

    async def _send(self, opcode: int, payload: bytes) -> None:

        mask = os.urandom(4)
        n = len(payload)
        head = bytes([0x80 | opcode])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 1 << 16:
            head += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack("!Q", n)
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.writer.write(head + mask + body)
        await self.writer.drain()

    async def send_text(self, text: str) -> None:
        await self._send(0x1, text.encode("utf-8"))

    async def ping(self) -> None:
        await self._send(0x9, b"tvgw")

    async def close(self, code: int = 1000) -> None:
        """Send a close frame first (a TV left with a 1006 close has refused new handshakes for
        minutes), then drop the connection."""

        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._send(0x8, struct.pack("!H", code)), 2)
        with contextlib.suppress(Exception):
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), 2)

    async def recv(self) -> str:
        """The next text message; pings are answered and pongs counted on the way."""

        parts: list[bytes] = []
        size = 0
        while True:
            b0, b1 = await self.reader.readexactly(2)
            fin, opcode, masked, n = b0 & 0x80, b0 & 0x0F, b1 & 0x80, b1 & 0x7F
            if n == 126:
                (n,) = struct.unpack("!H", await self.reader.readexactly(2))
            elif n == 127:
                (n,) = struct.unpack("!Q", await self.reader.readexactly(8))
            if masked:
                await self.close(1002)
                raise ProbeError("the TV sent a masked frame")
            if n > self.frame_max or size + n > self.frame_max:
                await self.close(1009)
                raise FrameTooBig(f"a frame of {n} bytes; the cap is {self.frame_max}")
            payload = await self.reader.readexactly(n)
            if opcode == 0x9:
                await self._send(0xA, payload)
                continue
            if opcode == 0xA:
                self.pongs += 1
                continue
            if opcode == 0x8:
                await self.close(1000)
                raise ProbeError("the TV closed the session")
            if opcode not in (0x0, 0x1, 0x2):
                await self.close(1002)
                raise ProbeError(f"unknown opcode {opcode}")
            parts.append(payload)
            size += n
            if fin:
                return b"".join(parts).decode("utf-8", "replace")


def _word(v) -> str | None:
    """A power field as the log keeps it: a plain word of the TV's vocabulary, or `other`."""
    if v is None:
        return None
    return v if isinstance(v, str) and _POWER_WORD.fullmatch(v) else "other"


def power_event(payload) -> dict:
    """The fields of a getPowerState message the probe keeps, each a plain word or `other`, and whether
    its state is one the research names (an unknown one is logged too: finding them is the point)."""
    p = payload if isinstance(payload, dict) else {}
    out = {f: w for f in POWER_FIELDS if (w := _word(p.get(f))) is not None}
    out["known"] = out.get("state") in POWER_STATES
    return out


def app_event(payload) -> dict:
    """The foreground app id, if it looks like one; anything else is `invalid` (the id is a string the
    TV chooses, and it ends up in files other tools read)."""
    p = payload if isinstance(payload, dict) else {}
    app = p.get("appId")
    if app is None:
        return {"appId": None}
    return {"appId": app if isinstance(app, str) and _APP_ID.fullmatch(app) else "invalid"}


class ProbeLog:
    """The probe's JSON-lines file: root-only (0600 in a 0700 directory), one line per event with the
    Pi's receive time, flushed at once so a killed probe loses nothing."""

    def __init__(self, path: str, clock=None):

        self.clock = clock or time.time
        os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        self.fh = open(fd, "a", encoding="utf-8", buffering=1)  # noqa: SIM115 - closed by close()

    def write(self, kind: str, **fields) -> None:

        line = json.dumps({"t": round(self.clock(), 3), "kind": kind, **fields}, sort_keys=True, default=str)
        self.fh.write(line[:4000] + "\n")

    def close(self) -> None:
        self.fh.close()


@dataclass
class ProbeConfig:
    host: str
    port: int = PROBE_PORT
    ssl_ctx: object | None = None
    client_key: str = ""
    manifest: dict = field(default_factory=dict)
    seconds: float = 26 * 3600.0
    ping: float = PROBE_PING
    pong_timeout: float = PROBE_PONG_TIMEOUT
    register_grace: float = PROBE_REGISTER_GRACE
    frame_max: int = PROBE_FRAME_MAX
    min_reconnect: float = PROBE_MIN_RECONNECT
    backoff: tuple[float, ...] = PROBE_BACKOFF


async def _session(cfg: ProbeConfig, log: ProbeLog, deadline: float, clock) -> None:
    """One session: connect, register with the stored key, subscribe, log until the deadline or until
    the session breaks. One task reads the socket and hands whole messages over a queue, so waiting
    with a timeout never cuts a frame in half."""
    ws = await _WebSocket.connect(cfg.host, cfg.port, cfg.ssl_ctx, cfg.frame_max)
    reader: asyncio.Task | None = None
    try:
        register = {"forcePairing": False, "pairingType": "PROMPT", "client-key": cfg.client_key}
        register["manifest"] = cfg.manifest
        await ws.send_text(json.dumps({"type": "register", "id": "register_0", "payload": register}))
        await _registered(ws, cfg)
        log.write("session.up")
        subs = {"power": POWER_URI, "app": APP_URI}
        for sid, uri in subs.items():
            await ws.send_text(json.dumps({"id": sid, "type": "subscribe", "uri": uri}))
        queue: asyncio.Queue = asyncio.Queue()

        async def read_all() -> None:
            try:
                while True:
                    await queue.put(await ws.recv())
            except Exception as e:  # handed to the loop below, which raises it there
                await queue.put(e)

        reader = asyncio.create_task(read_all())
        acked: set[str] = set()
        sent, pongs, waiting = clock(), ws.pongs, None
        while clock() < deadline:
            due = (waiting + cfg.pong_timeout) if waiting is not None else (sent + cfg.ping)
            wait = min(deadline, due if cfg.ping > 0 else deadline) - clock()
            try:
                item = await asyncio.wait_for(queue.get(), max(0.05, min(1.0, wait)))
            except TimeoutError:
                item = None
            if isinstance(item, BaseException):
                raise item
            if item is not None:
                _on_message(item, subs, acked, log)
            if ws.pongs != pongs:
                pongs, waiting = ws.pongs, None
            if waiting is not None and clock() - waiting > cfg.pong_timeout:
                raise ProbeError(f"no pong within {cfg.pong_timeout:.0f} s")
            if cfg.ping > 0 and waiting is None and clock() - sent >= cfg.ping:
                await ws.ping()
                sent = waiting = clock()
        log.write("session.end", why="the probe's time is up")
    finally:
        if reader is not None:
            reader.cancel()
            with contextlib.suppress(BaseException):
                await reader
        await ws.close(1000)


async def _registered(ws: _WebSocket, cfg: ProbeConfig) -> None:
    """Wait for `registered`; anything else means the TV did not take the key. Once the TV has answered
    with a pairing prompt, every way the session can end (silence, a closed socket, a close frame, a
    frame that is not JSON) is a refusal: a reconnect would register again and put a new prompt on the
    owner's screen, which the probe never does."""

    first = json.loads(await asyncio.wait_for(ws.recv(), PROBE_IO_TIMEOUT))
    if not isinstance(first, dict):
        raise PairingRejected("the TV answered the registration with something other than an object")
    if first.get("type") == "registered":
        return
    if (
        first.get("type") == "response"
        and isinstance(first.get("payload"), dict)
        and first["payload"].get("pairingType")
    ):
        # the TV is asking the owner to accept a new pairing: the stored key was not enough. A valid
        # key is answered at once, so a short grace tells the two apart without waiting on a prompt
        try:
            again = json.loads(await asyncio.wait_for(ws.recv(), cfg.register_grace))
        except Exception:
            raise PairingRejected("the TV asked for a new pairing (a prompt on the screen)") from None
        if not isinstance(again, dict):
            raise PairingRejected("the TV asked for a new pairing (a prompt on the screen)")
        if again.get("type") == "registered":
            return
        first = again
    raise PairingRejected(clean(first.get("error") or first.get("type") or "no answer")[:120])


def _on_message(raw: str, subs: dict[str, str], acked: set[str], log: ProbeLog) -> None:

    try:
        msg = json.loads(raw)
    except ValueError:
        log.write("frame.invalid")
        return
    sid = msg.get("id") if isinstance(msg, dict) else None
    if sid not in subs:
        return  # nothing else was asked
    payload = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    if msg.get("type") == "error" or payload.get("returnValue") is False:
        why = clean(msg.get("error") or payload.get("errorText") or "refused")[:200]
        log.write("sub.err", sub=sid, error=why)
        return
    if sid not in acked:
        acked.add(sid)
        log.write("sub.ok", sub=sid, subscribed=bool(payload.get("subscribed")))
    if sid == "power":
        log.write("power", **power_event(payload))
    else:
        log.write("app", **app_event(payload))


def carrier(tv_if: str):
    """A reader of the TV port's carrier: True, False, or None when the kernel does not say."""

    def read() -> bool | None:
        try:
            with open(f"/sys/class/net/{tv_if}/carrier", encoding="utf-8") as fh:
                return fh.read().strip() == "1"
        except OSError:
            return None

    return read


async def probe(cfg: ProbeConfig, log: ProbeLog, carrier_up=None, clock=None, sleep=None) -> int:
    """Hold sessions until `cfg.seconds` have passed. 0 when the time ran out, 2 when the TV refused
    the key (the probe never registers again after that). A failed or broken session is followed by
    PROBE_BACKOFF (5, 15, 30, then 60 s), never less than PROBE_MIN_RECONNECT after the previous
    attempt began; while the TV port has no carrier nothing is tried, and the carrier's edges are
    logged as `link` events."""

    clock = clock or time.monotonic
    sleep = sleep or asyncio.sleep
    carrier_up = carrier_up or (lambda: None)
    deadline = clock() + cfg.seconds
    failures = 0
    link = None
    log.write("probe.start", seconds=cfg.seconds)
    while clock() < deadline:
        up = carrier_up()
        if up != link:
            log.write("link", up=up)
            link = up
        if up is False:
            failures = 0  # a TV that comes back gets the short delays again
            await sleep(min(1.0, max(0.0, deadline - clock())))
            continue
        began = clock()
        try:
            await _session(cfg, log, deadline, clock)
            failures = 0
        except PairingRejected as e:
            log.write("pair.rejected", why=str(e))
            log.write(
                "probe.stop", why="pairing refused: run the pairing again at the TV; the probe never does"
            )
            return 2
        except (OSError, EOFError, TimeoutError, ValueError, ProbeError, asyncio.IncompleteReadError) as e:
            log.write("session.fail", error=clean(f"{type(e).__name__}: {e}")[:200])
            failures += 1
        if clock() >= deadline:
            break
        delay = (
            cfg.backoff[min(max(failures - 1, 0), len(cfg.backoff) - 1)] if failures else cfg.min_reconnect
        )
        delay = max(delay, cfg.min_reconnect - (clock() - began))
        await sleep(min(delay, max(0.0, deadline - clock())))
    log.write("probe.stop", why="time is up")
    return 0


def probe_main(ip: str, key_file: str, out: str, hours: float, tv_if: str) -> int:
    """`tvgw tvprobe`: the stored key and the library's manifest (the pairing was made with both), wss
    with the TV's self-signed certificate, the carrier of TV_IF. 1 when it cannot start."""

    if not os.path.exists(key_file):
        print(f"tvgw tvprobe: no key file at {key_file}; the probe never pairs (pair with bscpylgtvcommand)")
        return 1
    try:
        from bscpylgtv.manifest import MANIFEST  # optional dependency
        from bscpylgtv.storage_sqlitedict import StorageSqliteDict
    except ImportError as e:  # pragma: no cover - depends on the install
        print(f"tvgw tvprobe: bscpylgtv is not installed ({e})")
        return 1

    async def stored_key() -> str | None:
        storage = await StorageSqliteDict.create(key_file)
        return await storage.get_key(ip)

    key = asyncio.run(stored_key())
    if not key:
        print(f"tvgw tvprobe: no pairing for {ip} in {key_file}; the probe never pairs")
        return 1
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the TV's certificate is self-signed, as for the hourly reading
    cfg = ProbeConfig(ip, ssl_ctx=ctx, client_key=key, manifest=MANIFEST, seconds=hours * 3600)
    log = ProbeLog(out)
    try:
        rc = asyncio.run(probe(cfg, log, carrier(tv_if)))
    finally:
        log.close()
    print(f"tvgw tvprobe: {'stopped: the TV refused the key' if rc == 2 else 'done'}; events in {out}")
    return rc
