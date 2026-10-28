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


@dataclass
class TvReading:
    reachable: bool
    values: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def acr_off(self) -> bool | None:
        v = self.values.get(ACR_KEY)
        return None if v is None else v == "off"

    def lines(self) -> list[str]:
        if not self.reachable:
            return [f"TV unreachable ({self.error}): off, or in standby with Quick Start+ off"]
        out = [f"{k} = {v}" for k, v in self.values.items()]
        if self.acr_off is False:
            out.append("WARNING: Live Plus (ACR) is NOT off; check General > Additional Settings on the TV")
        return out

    def exit_code(self) -> int:
        """0 fine, 1 unreachable, 2 ACR on - what the hourly job keys off."""
        if not self.reachable:
            return 1
        return 2 if self.acr_off is False else 0


async def _read(ip: str, key_file: str, timeout: float) -> TvReading:
    try:
        from bscpylgtv import WebOsClient  # optional dependency
    except ImportError as e:  # pragma: no cover - depends on the install
        return TvReading(False, error=f"bscpylgtv not installed ({e})")
    try:
        c = await asyncio.wait_for(WebOsClient.create(ip, states=[], key_file_path=key_file), timeout)
        await asyncio.wait_for(c.connect(), timeout)
    except Exception as e:  # any failure here just means "not reachable now"
        return TvReading(False, error=type(e).__name__)
    r = TvReading(True)
    for cat, keys in READS:
        for k in keys:
            try:
                res = await asyncio.wait_for(c.get_system_settings(cat, [k]), timeout)
                r.values[f"{cat}.{k}"] = clean(res.get("settings", {}).get(k))
            except Exception as e:  # a TV that stalls or refuses one key must not hide the others
                r.values[f"{cat}.{k}"] = f"ERR {type(e).__name__} {str(e)[:60]}"
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
    """Read the TV; never hangs: each call gets `timeout`, the whole reading four times that."""
    try:
        return asyncio.run(asyncio.wait_for(_read(ip, key_file, timeout), timeout * 4))
    except TimeoutError:
        return TvReading(False, error="TimeoutError")
