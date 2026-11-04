"""Samsung Tizen's REST interface (tcp/8001): read a Samsung TV every hour without pairing.

`GET http://<TV_IP>:8001/api/v2/` answers without a token and puts nothing on the TV's screen, with the
TV's default settings, on every published sample from 2019 to 2025 (Home Assistant's samsungtv bridge,
the samsungtvws library and the raw replies in their issues). Pairing is no option: on 2024 sets running
One UI Tizen 9 builds 2115 and 2130 the remote channel times out or answers `ms.channel.unauthorized`
without ever showing the prompt (Home Assistant #179510, samsungtvws #184), so this module has none.

What a reading sends, and nothing else: the one request in REQUEST, to the TV's address literal, once.
It is built by hand on a plain socket, so its bytes are this file's constant: never a POST (a POST to
/api/v2/applications/<id> launches that app on some sets without pairing, cleanyourtv #441), never the
remote-control WebSocket (opening it can switch a set on: Home Assistant's bridge checks PowerState
first for that reason), never a key press, never Wake-on-LAN. One connection, CONNECT_TIMEOUT to open
it and DEADLINE for the whole reply, at most REPLY_MAX of body, no redirect followed, no retry: a TV
that does not answer is off, and the next hourly reading asks again.

What it keeps is listed in KEEP and the derived keys of `device_values()`. What it never keeps is the
reply's NEVER_STORE fields: `ssid` holds the BSSID of the access point when the TV is on Wi-Fi, which
public Wi-Fi databases turn into the home's location, so it is read for its presence alone and never
stored, printed or put into an error; `wifiMac` is there even when the TV is wired, so it says nothing
about Wi-Fi; `duid`, `id` and `udn` are one UUID that some sets make anew at every boot (Home Assistant
#169628), so nothing keys on it; `name` is what the owner typed; `ip` and `developerIP` are addresses.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from dataclasses import dataclass, field

from tvgw import lgwebos

PROFILE = "samsung-tizen"  # the one profile whose TV this module reads (cli.cmd_tvcheck)
REST_PORT = 8001
REST_PATH = "/api/v2/"
REQUEST = (
    "GET " + REST_PATH + " HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nUser-Agent: tvgw\r\n"
    "Connection: close\r\n\r\n"
)
CONNECT_TIMEOUT = 3.0  # seconds to open the connection
DEADLINE = 8.0  # seconds for the whole exchange, from the first byte sent to the last read
REPLY_MAX = 64 * 1024  # bytes of body; the published replies are under 2 KB
HEAD_MAX = 16 * 1024  # bytes of status line and headers
SMART_TV = "Samsung SmartTV"  # device.type of every Samsung TV sample; a soundbar is not one
# the reply's fields this module never keeps, prints or lets into an error (the module docstring says why)
NEVER_STORE = ("ssid", "wifiMac", "duid", "id", "udn", "ip", "name", "developerIP")
# the Tizen version each model year shipped with (Samsung Developers, "General specifications", read
# 2026-11-04; the samsung-tizen profile's header carries the same table with its sources)
TIZEN_BY_YEAR = {
    2016: "2.4", 2017: "3.0", 2018: "4.0", 2019: "5.0", 2020: "5.5", 2021: "6.0", 2022: "6.5",
    2023: "7.0", 2024: "8.0", 2025: "9.0", 2026: "10.0",
}  # fmt: skip
# the end of device.model after an upgrade in place, and the Tizen it means: `23_X22U_UHD_T09`,
# `24_KSUE_UB_T09` and `24_PTM_FTV_T09` are 2023 and 2024 sets running One UI Tizen 9 (three samples)
UPGRADE_SUFFIX = {"_T09": "9"}
# PowerState in the vocabulary the brief and the store already use (queries.AWAKE counts Active as on;
# Active Standby, LG's word for off with the network kept up, is off). A Frame showing art says standby
POWER = {"on": "Active", "standby": "Active Standby"}
# how a reading ended, as `tvgw tvcheck` exits (lgwebos' codes where they mean the same; 5 is new)
OK, UNREACHABLE, SECOND_PATH, NOT_READ = 0, 1, 3, 5
NOT_A_SAMSUNG = "not a Samsung TV"
_YEAR = re.compile(r"(\d{2})_[A-Za-z0-9_]+")
_SUFFIX = re.compile(r"_T\d{2}$")
_PLAIN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")  # a model, a platform code, a firmware string
_COUNTRY = re.compile(r"[A-Z]{2}")
_STATUS = re.compile(rb"HTTP/1\.[01] (\d{3})(?: [^\r\n]*)?")
_MAC = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f])")


class Refused(Exception):
    """The TV answered with something this reader does not take: another status, no HTTP, a body over
    REPLY_MAX, no JSON object. `reason` is one of this module's own phrases, never text from the reply."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def fetch(ip: str, port: int = REST_PORT, deadline: float = DEADLINE) -> dict:
    """The TV's device information: REQUEST, once, to the IPv4 literal `ip`. Raises ValueError for
    anything but an IPv4 literal (no name that could resolve elsewhere), OSError when nothing answers in
    time (TimeoutError past `deadline`), and Refused for an answer this reader does not take."""
    addr = ipaddress.IPv4Address(ip)
    end = time.monotonic() + deadline
    data = bytearray()
    with socket.create_connection((str(addr), port), timeout=min(CONNECT_TIMEOUT, deadline)) as sock:
        sock.sendall(REQUEST.format(host=f"{addr}:{port}").encode("ascii"))
        while True:
            left = end - time.monotonic()
            if left <= 0:
                raise TimeoutError("no whole reply in time")
            sock.settimeout(left)
            chunk = sock.recv(16384)
            if not chunk:
                break
            data += chunk
            if len(data) > HEAD_MAX + REPLY_MAX + 4:
                raise Refused("reply over 64 KiB")
            if _complete(bytes(data)):  # a server that keeps the connection open is not waited for
                break
    return parse(bytes(data))


def _complete(raw: bytes) -> bool:
    """Whether `raw` holds a whole response by its own framing: the headers and Content-Length bytes,
    or every chunk to the last. Without either, the end is the TV closing the connection."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        return False
    fields = {}
    for line in head.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            fields[name.strip().lower()] = value.strip()
    if b"chunked" in fields.get(b"transfer-encoding", b"").lower():
        try:
            _unchunk(body)
        except Refused:
            return False
        return True
    length = fields.get(b"content-length", b"")
    return length.isdigit() and len(body) >= int(length)


def parse(raw: bytes) -> dict:
    """One HTTP response, as `fetch` read it to the end, to the JSON object of its body; Refused for
    anything else. A redirect is a status like any other: refused, never followed."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep or len(head) > HEAD_MAX:
        raise Refused("not HTTP")
    lines = head.split(b"\r\n")
    m = _STATUS.fullmatch(lines[0])
    if m is None:
        raise Refused("not HTTP")
    if m.group(1) != b"200":
        raise Refused(f"HTTP {int(m.group(1))}")
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon:
            raise Refused("not HTTP")
        headers[name.strip().lower()] = value.strip()
    if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
        body = _unchunk(body)
    elif b"content-length" in headers:
        if not headers[b"content-length"].isdigit():
            raise Refused("not HTTP")
        n = int(headers[b"content-length"])
        if n > REPLY_MAX:
            raise Refused("reply over 64 KiB")
        if len(body) < n:
            raise Refused("reply cut short")
        body = body[:n]
    if len(body) > REPLY_MAX:
        raise Refused("reply over 64 KiB")
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):
        raise Refused("not JSON") from None
    if not isinstance(data, dict):
        raise Refused("not a JSON object")
    return data


def _unchunk(body: bytes) -> bytes:
    out = bytearray()
    while True:
        size_line, sep, body = body.partition(b"\r\n")
        size = size_line.split(b";", 1)[0].strip()
        if not sep or not size or len(size) > 8 or not re.fullmatch(rb"[0-9A-Fa-f]+", size):
            raise Refused("not HTTP")
        n = int(size, 16)
        if n == 0:
            return bytes(out)
        if len(out) + n > REPLY_MAX:
            raise Refused("reply over 64 KiB")
        if len(body) < n + 2 or body[n : n + 2] != b"\r\n":
            raise Refused("reply cut short")
        out += body[:n]
        body = body[n + 2 :]


def _device(info: dict) -> dict:
    dev = info.get("device")
    return dev if isinstance(dev, dict) else {}


def is_samsung_tv(info: dict) -> bool:
    """Whether the reply is a Samsung TV's: device.type (or the top-level type) is SMART_TV, and
    device.OS, where the reply has it, is Tizen. A Samsung soundbar answers some of the same discovery
    signals as a TV (Home Assistant #170287, #171990) and is not one."""
    dev = _device(info)
    kind = dev.get("type", info.get("type"))
    os_name = dev.get("OS")
    return kind == SMART_TV and (os_name is None or (isinstance(os_name, str) and os_name.lower() == "tizen"))


def _plain(value) -> str | None:
    """A model, a platform code or a firmware string as stored: plain letters, digits and `_.-`, else
    `invalid`; None when the reply has no such value."""
    if value is None or isinstance(value, bool) or not isinstance(value, str | int):
        return None if value is None else "invalid"
    text = str(value).strip()
    if not text:
        return None
    return text if _PLAIN.fullmatch(text) else "invalid"


def _flag(value) -> str | None:
    """`true`/`false` from a JSON boolean or the strings the TV writes them as; None when absent."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower()
    return None if value is None else "unknown"


def year_of(code: str) -> int | None:
    """The model year from device.model (`20_NIKEL_UHD` -> 2020); None without a year prefix."""
    m = _YEAR.fullmatch(code or "")
    return 2000 + int(m.group(1)) if m and 15 <= int(m.group(1)) <= 40 else None


def tizen_of(code: str) -> str | None:
    """The Tizen the model code says the TV runs, with what says so: `9 (model code _T09)` after an
    upgrade in place, `unknown (model code ends _T10)` for an ending UPGRADE_SUFFIX does not know, else
    the version its year shipped with, `5.5 (model year 2020)`. None when the code gives neither."""
    end = _SUFFIX.search(code or "")
    if end:
        known = UPGRADE_SUFFIX.get(end.group(0))
        return (
            f"{known} (model code {end.group(0)})" if known else f"unknown (model code ends {end.group(0)})"
        )
    year = year_of(code)
    return f"{TIZEN_BY_YEAR[year]} (model year {year})" if year in TIZEN_BY_YEAR else None


def device_values(info: dict) -> dict[str, str]:
    """The reply as `key = value` settings for tvcheck.txt. A field the reply leaves out is absent, never
    guessed; NEVER_STORE fields never reach a value, and a value that holds one of them is `invalid`."""
    dev = _device(info)
    out: dict[str, str] = {"rest.reply": "ok"}
    for field_name, key in (("modelName", "model"), ("model", "platform"), ("firmwareVersion", "firmware")):
        value = _plain(dev.get(field_name))
        if value is not None:
            out[key] = value
    code = out.get("platform", "")
    if (year := year_of(code)) is not None:
        out["model.year"] = str(year)
    if (tizen := tizen_of(code)) is not None:
        out["tizen"] = tizen
    if out.get("firmware", "").lower() == "unknown":  # every sample from 2019 to 2025 says Unknown
        out["firmware"] = "unknown"
    raw = dev.get("PowerState")
    # no PowerState (sets before 2019): the TV answered, and Samsung's IP server stops about a minute
    # after the TV goes to standby, so it is on
    out["power"] = "Active" if raw is None else POWER.get(str(raw).strip().lower(), "unknown")
    # Wi-Fi joined: networkType says wireless, or the reply carries ssid, which it has only on Wi-Fi.
    # Both keys or neither: one network key without the Wi-Fi state would end the brief's "Not checked"
    # line with nothing checked (queries.not_checked counts any path key as a reading of the paths)
    network = str(dev.get("networkType") or "").strip().lower()
    on_wifi = bool(dev.get("ssid")) or network == "wireless"
    if on_wifi or network == "wired":
        out["network.wired.state"] = "connected" if network == "wired" else "unknown"
        out["network.wifi.state"] = "connected" if on_wifi else "disconnected"
    for field_name, key in (("smartHubAgreement", "smarthub.agreement"), ("FrameTVSupport", "frame")):
        flag = _flag(dev.get(field_name))
        if flag is not None:
            out[key] = flag
    country = dev.get("countryCode")
    if isinstance(country, str) and _COUNTRY.fullmatch(country.strip()):
        out["country"] = country.strip()
    return scrubbed(out, dev)


def _secrets(dev: dict) -> list[str]:
    found = []
    for name in NEVER_STORE:
        value = dev.get(name)
        if isinstance(value, str | int) and not isinstance(value, bool) and len(str(value).strip()) >= 6:
            found.append(str(value).strip())
    return found


def scrubbed(values: dict[str, str], dev: dict) -> dict[str, str]:
    """`values` with any value that holds a NEVER_STORE field of `dev`, or anything shaped like a MAC
    address (a BSSID is one), replaced by `invalid`."""
    secrets = [s.lower() for s in _secrets(dev)]
    return {
        k: "invalid" if _MAC.search(v) or any(s in v.lower() for s in secrets) else v
        for k, v in values.items()
    }


@dataclass
class Reading:
    reachable: bool
    values: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def read(self) -> bool:
        """Whether the TV answered as a Samsung TV, so the values are its own."""
        return self.reachable and self.values.get("rest.reply") == "ok"

    @property
    def second_paths(self) -> list[str]:
        """The ways the TV reports it can reach a network besides its cable: Wi-Fi joined, here."""
        return [
            label
            for key, label in lgwebos.SECOND_PATHS.items()
            if lgwebos.is_second_path(key, self.values.get(key))
        ]

    def lines(self) -> list[str]:
        if not self.reachable:
            return [
                f"TV unreachable ({self.error}): off, or asleep (a Samsung stops answering about a minute"
                " after it goes to standby)"
            ]
        out = [f"{k} = {v}" for k, v in self.values.items()]
        if not self.read:
            out.append(
                "WARNING: the device at the TV's address did not answer as a Samsung TV"
                f" ({self.values.get('rest.reply', 'no reply')}): nothing was read; check that PROFILE"
                " names this TV's profile"
            )
        elif self.second_paths:
            out.append(
                "WARNING: the TV has a second network path ("
                + ", ".join(self.second_paths)
                + "): traffic can leave around the gateway; Settings > All Settings > Connection > Network"
                " > Expert Settings > Wi-Fi"
            )
        return out

    def exit_code(self) -> int:
        """0 read, 1 no answer (off), 3 a second network path, 5 an answer that is not a Samsung TV's:
        what the hourly job keys off. tvgw-analyze keeps the reading for every code but 1 and 4."""
        if not self.reachable:
            return UNREACHABLE
        if not self.read:
            return NOT_READ
        return SECOND_PATH if self.second_paths else OK


def read(ip: str, port: int = REST_PORT, get=fetch) -> Reading:
    """The hourly reading: one GET, never anything else. No answer is `unreachable` with the error's type
    name only; an answer this reader refuses, or one that is not a Samsung TV's, is kept as `rest.reply`
    with this module's reason, so the store records it once and the next change of it."""
    try:
        info = get(ip, port)
    except Refused as e:
        return Reading(True, {"rest.reply": f"refused ({e.reason})"})
    except (OSError, ValueError) as e:
        return Reading(False, error=type(e).__name__)
    if not is_samsung_tv(info):
        return Reading(True, {"rest.reply": NOT_A_SAMSUNG})
    return Reading(True, device_values(info))


@dataclass(frozen=True)
class Identity:
    """What discovery learns from the same GET: `tv` for a Samsung TV, `not-tv` for a device that
    answered with JSON but not as one (a soundbar), with the TV's model and year where it gave them."""

    kind: str
    model: str = ""
    year: str = ""


def identify(ip: str, port: int = REST_PORT, get=fetch) -> Identity | None:
    """discover's question, asked only of a device another signal names Samsung: the REST reply's kind.
    None when nothing usable answered."""
    try:
        info = get(ip, port)
    except (Refused, OSError, ValueError):
        return None
    if not is_samsung_tv(info):
        return Identity("not-tv")
    values = device_values(info)
    model = values.get("model", "")
    return Identity("tv", "" if model == "invalid" else model, values.get("model.year", ""))
