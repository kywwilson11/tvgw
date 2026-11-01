"""LG webOS LAN API (SSAP, tcp/3000): read the TV's privacy-relevant settings.

Needs the optional `bscpylgtv` dependency (`pip install tvgw[lgwebos]`) and a one-time pairing
(`bscpylgtvcommand -p <key file> <tv ip> get_software_info`, accept the prompt on the TV).
Firmware 04.64 (webOS 5) refuses writes through this API (its `isCallAllowed` guard rejects the
Luna side-door every LAN tool uses), so this module only reads.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field

READS = (
    ("option", ("livePlus", "zipcode", "country", "audioGuidance", "storeMode")),
    ("network", ("deviceName", "wolwowlOnOff")),
    ("other", ("simplinkEnable",)),
)
ACR_KEY = "option.livePlus"
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
                r.values[f"{cat}.{k}"] = clean(res.get("settings", {}).get(k))
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
