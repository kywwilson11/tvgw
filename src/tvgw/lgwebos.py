"""LG webOS LAN API (SSAP, wss on tcp/3001): read the TV's privacy-relevant settings.

Needs the optional `bscpylgtv` dependency (`pip install tvgw[lgwebos]`) and a one-time pairing,
`sudo tvgw tv pair` or `tvgw setup`, accepted on the TV with the remote. A reading never pairs: the
library registers on every connection, and a registration without a stored key puts the pairing prompt
on the TV's screen, so `read()` connects only when the key file holds a key for the TV and `pair()` is
the one call that may register (design decision 54).

Every connection sends a manifest, and LG checks it each time, not at pairing. The library's default is
the signed "LG Remote App" manifest, which the reference CX (webOS 5, firmware 04.64.00) was paired with
and still takes; LG's newer firmware (webOS 26 from 43.20, some webOS 25 sets) answers it with
`403 Pairing rejected: blacklisted certificate detected` and shows no prompt, and a key that worked can
stop working after the TV's update. So a new pairing uses tvgw's own unsigned, read-only manifest
(`lg-webos.manifest.json` beside the profile), the manifest each key was made with is recorded in the key
store (lgkeys.py), and the reading sends that one. Nothing here switches a stored key's manifest or pairs
again on its own; `tvgw tv pair --manifest signed` is the owner's fallback.

A reading opens one short connection of its own first (`handshake()`): the `hello` reply, which needs
no key and puts nothing on the screen, says which webOS the TV runs (`deviceOSReleaseVersion`), and the
registration with the stored key says whether the TV still takes it. A refusal (a 403, or a pairing
prompt in place of `registered`) is recorded in the key store and the hourly reading stops connecting
until `tvgw tv pair` runs: a refused key sent every hour is a prompt on the screen every hour, and LG's
"403 too many pairing requests" lock clears only by unplugging the TV. Port 3001 only, with a connect
timeout: port 3000 is gone on 2022+ firmware and can accept the connection and then hang for minutes.

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
from importlib import resources

from tvgw import lgkeys

READS = (
    ("option", ("livePlus", "zipcode", "country", "audioGuidance", "storeMode")),
    # (ledger) bleAdvertisingOnOff: recorded only, never a red line (Bluetooth carries no data on its own)
    ("network", ("deviceName", "wolwowlOnOff", "bleAdvertisingOnOff")),
    ("other", ("simplinkEnable",)),
)
ACR_KEY = "option.livePlus"
# (pairing) the error of a reading that asked nothing because the gateway holds no key for the TV
NOT_PAIRED = "not paired"
# (pairing) the error of a reading that asked nothing because the TV refused the stored key at an earlier
# reading (lgkeys.Pairing.refused): only `tvgw tv pair` clears it
KEY_REFUSED = "key refused"
PAIR_TIMEOUT = 60.0  # seconds per call while pairing: how long the owner has to accept the prompt on the TV
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

# ---- (W12) the per-document consent record, the standby switches and the TV's webOS ---------------------
# `eulaInfoNetwork` sits beside `eulaStatus` in every public list from webOS 5 to 26 (bscpylgtv's dumps).
# On a set that has downloaded its agreements it holds one entry per document with `id`, `version`,
# `accepted` and `updated` (REPORTED: one rooted webOS 25 write-up, 2026; not seen on the CX yet). Each
# document is stored as `eula.doc.<id>` = true/false (accepted: a false -> true flip is the agreement red
# line, through queries.consent_flips) and `agreement.<id>.updated` / `.version` (never a red line: the
# brief says the TV asks for the agreement again). Document ids seen on webOS 25 (REPORTED):
AGREEMENTS_KEY = "eulaInfoNetwork"
AGREEMENT_PREFIX = "agreement."
AGREEMENT_NAMES = {
    "S_ADG": "Viewing Information",
    "S_VNG": "Voice Information",
    "S_TAG": "Interest-Based Advertising",
    "S_MKT": "marketing",
    "S_PRG": "Privacy Policy",
}
_DOC_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}")
# the standby switches that keep the TV's network up while the screen is dark (LG: Always Ready, Quick
# Start+, TV On With Mobile). Read where the TV's generation lists them as readable (the profile's
# [[generations]] rows); `network.wolwowlOnOff` is in READS on every generation. Informational, never a
# red line: the brief explains a non-zero "While off" line with them (design decision 36)
STANDBY_KEYS = {
    "general.alwaysOn": "Always Ready",
    "option.quickStartMode": "Quick Start+",
    "network.wolwowlOnOff": "TV On With Mobile",
}
# the webOS release line (`deviceOSReleaseVersion`, major part) -> LG's marketing name. 7 to 9 are LG's
# developer site (webOS 22 = 7.x, 23 = 8.x, 24 = 9.x); 10 and 11 are what webOS 25 and 26 sets report
# (dumps, aiowebostv #718 and #720), not LG's word. test_profile.py holds this table to the profile's
# [[generations]] os_major rows
OS_GENERATIONS = {
    "3": "3", "4": "4", "5": "5", "6": "6", "7": "22", "8": "23", "9": "24", "10": "25", "11": "26",
}  # fmt: skip
_RELEASE = re.compile(r"\d{1,2}(\.\d{1,3}){0,2}")
SSAP_PORT = 3001  # wss only: 3000 is gone on 2022+ firmware and can hang after power-on (aiowebostv #744)
CONNECT_TIMEOUT = 5.0  # seconds for the TCP and TLS connect of the handshake: fail fast, never hang
HELLO_TIMEOUT = 5.0  # seconds for the `hello` reply, which needs no key
MANIFEST_FILE = "lg-webos.manifest.json"  # tvgw's unsigned, read-only manifest, beside the profile


def generation_from_release(release: str | None) -> str:
    """The webOS generation (LG's name: 5, 6, 22 .. 26) for a `deviceOSReleaseVersion` such as 11.2.0,
    or "" for none, an unreadable one, or a major this table does not know (webOS 27 one day)."""
    if not isinstance(release, str) or not _RELEASE.fullmatch(release.strip()):
        return ""
    return OS_GENERATIONS.get(release.strip().split(".")[0], "")


def unsigned_manifest_path() -> str:
    """The file of tvgw's unsigned, read-only manifest, as the library takes it (`manifest_file_path`)."""
    return str(resources.files("tvgw.profiles") / MANIFEST_FILE)


def unsigned_manifest() -> dict:
    """tvgw's manifest: read permissions only, no `signed` block and no `signatures`, so LG's blacklist
    of the "LG Remote App" certificate does not apply to it (test_lgwebos.py holds it to that)."""
    return json.loads((resources.files("tvgw.profiles") / MANIFEST_FILE).read_text(encoding="utf-8"))


def manifest_for(kind: str) -> dict:
    """The manifest a connection sends for a key made with `kind`: the library's signed default for
    `signed` (the CX's key), tvgw's own for `unsigned`."""
    if kind == "unsigned":
        return unsigned_manifest()
    from bscpylgtv.manifest import MANIFEST  # optional dependency

    return MANIFEST


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


def agreements(settings) -> dict[str, str]:
    """(W12) `eulaInfoNetwork` as settings-like keys: for each document, `eula.doc.<id>` (accepted:
    true, false or unknown), `agreement.<id>.updated` (true, false or unknown) and `agreement.<id>.version`.
    The record is a list of entries, or a table keyed by id (both shapes are read; neither is verified on
    a set here). An entry without a plain id, or a record of another shape, gives nothing: never a guess."""
    record = settings.get(AGREEMENTS_KEY) if isinstance(settings, dict) else None
    entries: list[tuple[str, dict]] = []
    if isinstance(record, list):
        entries = [(e.get("id"), e) for e in record if isinstance(e, dict)]
    elif isinstance(record, dict):
        entries = [(k, v if isinstance(v, dict) else {}) for k, v in record.items()]
    out: dict[str, str] = {}

    def word(v) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, str) and v.lower() in ("true", "false"):
            return v.lower()
        return "unknown"

    for doc, entry in entries:
        if not isinstance(doc, str) or not _DOC_ID.fullmatch(doc):
            continue
        out[f"{CONSENT_PREFIX}doc.{doc}"] = word(entry.get("accepted"))
        out[f"{AGREEMENT_PREFIX}{doc}.updated"] = word(entry.get("updated"))
        version = entry.get("version")
        if version is not None:
            out[f"{AGREEMENT_PREFIX}{doc}.version"] = clean(version)[:40]
    return out


def agreement_name(doc: str) -> str:
    """`Viewing Information (S_ADG)` for a document id the research names, else the id alone."""
    name = AGREEMENT_NAMES.get(doc)
    return f"{name} ({doc})" if name else doc


# ISO 3166-1 alpha-3 -> alpha-2 for the codes LG's TVs report in `country` (the software info's
# country, three letters on the CX) and `option.country`; LG's host prefixes are two lower-case letters
# (us., ca., de., nl. seen in the field). A code outside this table, or a two-letter one, is lower-cased
# as it is. Where LG's prefix differs from ISO (unverified: none known) LG_COUNTRY_PREFIXES says so.
ISO3_TO_ISO2 = {
    "USA": "us", "CAN": "ca", "MEX": "mx", "BRA": "br", "ARG": "ar", "CHL": "cl", "COL": "co", "PER": "pe",
    "GBR": "gb", "IRL": "ie", "DEU": "de", "FRA": "fr", "ITA": "it", "ESP": "es", "PRT": "pt", "NLD": "nl",
    "BEL": "be", "LUX": "lu", "AUT": "at", "CHE": "ch", "POL": "pl", "CZE": "cz", "SVK": "sk", "HUN": "hu",
    "ROU": "ro", "BGR": "bg", "GRC": "gr", "HRV": "hr", "SVN": "si", "SRB": "rs", "DNK": "dk", "SWE": "se",
    "NOR": "no", "FIN": "fi", "EST": "ee", "LVA": "lv", "LTU": "lt", "UKR": "ua", "TUR": "tr", "ISR": "il",
    "ARE": "ae", "SAU": "sa", "EGY": "eg", "ZAF": "za", "NGA": "ng", "KEN": "ke", "MAR": "ma",
    "RUS": "ru", "KAZ": "kz", "IND": "in", "PAK": "pk", "BGD": "bd", "LKA": "lk", "CHN": "cn", "HKG": "hk",
    "TWN": "tw", "KOR": "kr", "JPN": "jp", "SGP": "sg", "MYS": "my", "THA": "th", "VNM": "vn", "IDN": "id",
    "PHL": "ph", "AUS": "au", "NZL": "nz",
}  # fmt: skip
LG_COUNTRY_PREFIXES: dict[str, str] = {}  # ISO alpha-2 -> LG's host prefix where they differ (none verified)
_CC = re.compile(r"[a-z]{2}")


def country_code(value: str | None) -> str:
    """The two-letter, lower-case country prefix LG's hosts use (`de.nextlgsdp.com`) for a country the
    TV reported: ISO alpha-3 (`USA`) through ISO3_TO_ISO2, alpha-2 (`US`, `us`) as it is, anything
    else "". The hourly reading's `country` and `option.country` values go through here."""
    if not isinstance(value, str):
        return ""
    v = value.strip()
    if len(v) == 3 and v.upper() in ISO3_TO_ISO2:
        cc = ISO3_TO_ISO2[v.upper()]
    elif len(v) == 2 and v.isalpha():
        cc = v.lower()
    else:
        return ""
    return LG_COUNTRY_PREFIXES.get(cc, cc) if _CC.fullmatch(cc) else ""


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


def standby_on(values: dict[str, str]) -> list[str]:
    """The standby switches a reading says are on, by LG's names: what keeps the TV's network up while
    the screen is dark. `unknown`, a read error and an absent key are not on."""
    return [label for key, label in STANDBY_KEYS.items() if values.get(key) in ("on", "true")]


def agreements_pending(values: dict[str, str]) -> list[str]:
    """The agreement documents a reading says the TV has updated and nobody has accepted: the TV asks
    for them again at the next use of a smart service (LG re-shows updated terms)."""
    out = []
    for key, value in values.items():
        if key.startswith(AGREEMENT_PREFIX) and key.endswith(".updated") and value == "true":
            doc = key[len(AGREEMENT_PREFIX) : -len(".updated")]
            if values.get(f"{CONSENT_PREFIX}doc.{doc}") != "true":
                out.append(doc)
    return out


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
        if not self.reachable and self.error == NOT_PAIRED:
            return [
                "TV not paired: the gateway holds no key for it, so nothing was asked. Pair once with"
                " `sudo tvgw tv pair` and accept the prompt on the TV"
            ]
        if not self.reachable and self.error and self.error.startswith(KEY_REFUSED):
            return [
                f"TV refused the gateway's key ({self.error}): nothing was asked, and the hourly reading"
                " stays off until you pair again with `sudo tvgw tv pair` (with the TV on)"
            ]
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
        if on := standby_on(self.values):
            out.append(f"NOTE: {', '.join(on)} on: the TV keeps its network up while the screen is off")
        for doc in agreements_pending(self.values):
            out.append(f"NOTE: the TV asks you to accept {agreement_name(doc)} again; it is not accepted")
        return out

    def exit_code(self) -> int:
        """0 fine, 1 unreachable, 2 ACR on, 3 a second network path, 4 not paired (nothing was asked),
        5 the TV refused the key (nothing was asked; `tvgw tv pair` is the fix) - what the hourly job
        keys off."""
        if not self.reachable:
            if self.error == NOT_PAIRED:
                return 4
            return 5 if self.error and self.error.startswith(KEY_REFUSED) else 1
        if self.second_paths:
            return 3
        return 2 if self.acr_off is False else 0


async def _stored_key(key_file: str, ip: str) -> str | None:
    """The pairing key the key file holds for `ip`, read through the library's own storage, as the
    reading would read it. A missing file is never opened, because opening it creates it; a file that
    cannot be read, or no library, holds no usable key."""
    if not os.path.isfile(key_file):
        return None
    try:
        from bscpylgtv.storage_sqlitedict import StorageSqliteDict  # optional dependency

        storage = await StorageSqliteDict.create(key_file)
    except Exception:  # not the library's database, unreadable, or no library: no key to use
        return None
    try:
        key = await storage.get_key(ip)
    except Exception:
        key = None
    with contextlib.suppress(Exception):  # the database's writer thread; nothing was written
        storage.db.close()
    return key if isinstance(key, str) and key else None


def has_key(key_file: str, ip: str) -> bool:
    """Whether the gateway is paired with the TV at `ip`: the key file holds a key for that address.
    Reads only; a missing key file stays missing."""
    return asyncio.run(_stored_key(key_file, ip)) is not None


# ---- (W12) the handshake: `hello`, then the stored key, on one short connection of tvgw's own ----------
@dataclass
class Handshake:
    """What one connection learned before any reading: the TV's release (`deviceOSReleaseVersion`, e.g.
    5.6.2 or 11.2.0) and OS version (`deviceOSVersion`), whether it took the stored key (`registered`:
    True, False for a refusal, None when no key was sent), the refusal's reason in the TV's words, and
    the error when the TV could not be reached at all."""

    release: str = ""
    os_version: str = ""
    registered: bool | None = None
    refused_why: str = ""
    error: str = ""

    @property
    def generation(self) -> str:
        return generation_from_release(self.release)


def _ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the TV's certificate is the one static self-signed leaf every LG has
    return ctx


async def _connect_ws(ip: str, timeout: float) -> _WebSocket:
    """One WebSocket to the TV on SSAP_PORT over TLS, within `timeout`. Patched in tests."""
    return await _WebSocket.connect(ip, SSAP_PORT, _ssl_context(), timeout=timeout)


def _hello_fields(payload) -> tuple[str, str]:
    """(release, os_version) from a `hello` payload, each a plain version string or ""; `deviceUUID`
    and everything else in the reply is dropped here and never stored."""
    p = payload if isinstance(payload, dict) else {}
    release = p.get("deviceOSReleaseVersion")
    os_version = p.get("deviceOSVersion")
    release = release.strip() if isinstance(release, str) and _RELEASE.fullmatch(release.strip()) else ""
    os_version = (
        os_version.strip() if isinstance(os_version, str) and _RELEASE.fullmatch(os_version.strip()) else ""
    )
    return release, os_version


async def _handshake_on(ws: _WebSocket, key: str | None, manifest: dict, timeout: float) -> Handshake:
    h = Handshake()
    try:
        await ws.send_text(json.dumps({"id": "hello", "type": "hello", "payload": {}}))
        first = json.loads(await asyncio.wait_for(ws.recv(), min(timeout, HELLO_TIMEOUT)))
        if isinstance(first, dict) and first.get("type") == "hello":
            h.release, h.os_version = _hello_fields(first.get("payload"))
    except Exception as e:  # a TV that does not answer hello still answers the registration
        h.error = f"hello: {type(e).__name__}"
    if key is None:
        return h
    register = {"forcePairing": False, "pairingType": "PROMPT", "client-key": key, "manifest": manifest}
    try:
        await ws.send_text(json.dumps({"type": "register", "id": "register_0", "payload": register}))
        await _registered(ws, ProbeConfig(host="", register_grace=PROBE_REGISTER_GRACE))
        h.registered, h.error = True, ""
    except PairingRejected as e:
        h.registered, h.refused_why, h.error = False, clean(str(e))[:200], ""
    except Exception as e:
        h.error = type(e).__name__
    return h


async def handshake(ip: str, key: str | None, manifest: dict, timeout: float = CONNECT_TIMEOUT) -> Handshake:
    """One connection: `hello` (no key, nothing on the screen), then, with a key, the registration that
    says whether the TV still takes it. With a key the TV does not take, the TV shows its prompt once
    here, and the caller records the refusal so that no reading sends the key again. Never hangs: the
    connect, the hello and the registration each have `timeout`."""
    try:
        ws = await _connect_ws(ip, timeout)
    except Exception as e:
        return Handshake(error=type(e).__name__)
    try:
        return await asyncio.wait_for(_handshake_on(ws, key, manifest, timeout), timeout * 3)
    except TimeoutError:
        return Handshake(error="TimeoutError")
    finally:
        with contextlib.suppress(Exception):
            await ws.close(1000)


def _extra_reads(generation: str, skip: tuple[str, ...]) -> list[tuple[str, str]]:
    """(W12) The standby keys the TV's generation lists as readable and the key store does not mark
    unreadable, as (category, key). The profile's [[generations]] rows decide, so the CX (webOS 5, which
    lists none of them beyond `network.wolwowlOnOff`, already in READS) asks the same keys it always did."""
    if not generation:
        return []
    from tvgw import profile  # here: profile imports nothing of this module

    try:
        g = profile.load("lg-webos").generation_for(webos=generation)
    except (OSError, ValueError):
        return []
    if g is None:
        return []
    read_already = {f"{cat}.{k}" for cat, keys in READS for k in keys}
    return [
        tuple(key.split(".", 1))
        for key in STANDBY_KEYS
        if key in g.readable and key not in read_already and key not in skip
    ]


def _refused_text(e: BaseException) -> str:
    """Whether a library error says the TV refused the call for want of permission (401): the key stays
    good, the key is just not allowed this read."""
    return "401" if "401" in str(e) else ""


async def _read(
    ip: str, key_file: str, timeout: float, r: TvReading, register: bool = False, manifest: str | None = None
) -> TvReading:
    """Fill `r`, which the caller holds: when the whole reading runs out of time, what was read so far
    is still there. Without `register`, a TV the key file holds no key for is never contacted, and one
    whose key the TV refused is never contacted again until `pair()` runs. `manifest` is the kind to send
    while pairing; a reading sends the kind the key store records for the key."""
    try:
        from bscpylgtv import WebOsClient  # optional dependency
    except ImportError as e:  # pragma: no cover - depends on the install
        r.error = f"bscpylgtv not installed ({e})"
        return r
    key = await _stored_key(key_file, ip)
    if not register and key is None:
        r.error = NOT_PAIRED
        return r
    rec = lgkeys.record(key_file, ip)
    kind = manifest or (rec.manifest if rec else "signed")
    if not register and rec is not None and rec.refused:
        when = time.strftime("%Y-%m-%d", time.localtime(rec.refused_at))
        r.error = f"{KEY_REFUSED} since {when}: {rec.refused_why or 'the TV did not take it'}"
        return r
    # (W12) the handshake: the TV's webOS from `hello`, and whether it still takes the key. While pairing
    # the key is not sent here (the library registers once, below), so the prompt shows once at most
    h = await handshake(ip, None if register else key, manifest_for(kind) if not register else {}, timeout)
    if h.registered is False:
        lgkeys.refused(key_file, ip, h.refused_why or "the TV asked for a new pairing")
        r.error = f"{KEY_REFUSED} now: {h.refused_why or 'the TV asked for a new pairing'}"
        return r
    if h.error and not h.error.startswith("hello") and not register:
        r.error = h.error  # the TV could not be reached: off, or asleep
        return r
    if h.release:
        lgkeys.seen(key_file, ip, h.release, h.os_version, h.generation)
    try:
        kwargs = {"manifest_file_path": unsigned_manifest_path()} if kind == "unsigned" else {}
        c = await asyncio.wait_for(
            WebOsClient.create(ip, states=[], key_file_path=key_file, **kwargs), timeout
        )
        await asyncio.wait_for(c.connect(), timeout)
    except Exception as e:  # any failure here just means "not reachable now"
        r.error = type(e).__name__
        return r
    r.reachable, r.error = True, None
    skip = rec.unreadable if rec else ()
    for cat, keys in (*READS, *((cat, (k,)) for cat, k in _extra_reads(h.generation, skip))):
        for k in keys:
            try:
                res = await asyncio.wait_for(c.get_system_settings(cat, [k]), timeout)
                value = res.get("settings", {}).get(k)
                if value is None and f"{cat}.{k}" in UNKNOWN_IF_MISSING:  # (ledger)
                    value = "unknown"
                r.values[f"{cat}.{k}"] = clean(value)
            except Exception as e:  # a TV that stalls or refuses one key must not hide the others
                r.values[f"{cat}.{k}"] = f"ERR {type(e).__name__} {str(e)[:60]}"
                if _refused_text(e) and f"{cat}.{k}" in STANDBY_KEYS:  # (W12) asked once, recorded
                    lgkeys.unreadable(key_file, ip, f"{cat}.{k}")
    # (W12) the TV's webOS, from the handshake: the record of its software where getCurrentSWInformation
    # answers 401 (webOS 26 with an unsigned manifest). ERR values are printed, never stored
    r.values["webos.release"] = h.release or f"ERR hello {h.error or 'no release in the reply'}"[:80]
    r.values["webos.os"] = h.os_version or "unknown"
    r.values["webos.generation"] = h.generation or "unknown"
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
    # (W12) the per-document half of the consent record, on the same short clock, unless the TV said 401
    # to it before (then it is not asked again until the next pairing)
    if AGREEMENTS_KEY not in skip:
        try:
            res = await asyncio.wait_for(
                c.get_system_settings(CONSENT_CATEGORY, [AGREEMENTS_KEY]), min(timeout, CONSENT_TIMEOUT)
            )
            r.values.update(agreements((res or {}).get("settings", {})))
        except Exception as e:
            r.values[f"{AGREEMENT_PREFIX}status"] = f"ERR {type(e).__name__} {str(e)[:60]}"
            if _refused_text(e):
                lgkeys.unreadable(key_file, ip, AGREEMENTS_KEY)
    with contextlib.suppress(Exception):  # nothing left to do with a half-closed socket
        await asyncio.wait_for(c.disconnect(), timeout)
    return r


def clean(v) -> str:
    """One line of printable text: values come from the TV (its deviceName is user-set) and end up in
    files other tools parse line by line."""
    return "".join(ch if ch.isprintable() else " " for ch in str(v))[:200]


def read(ip: str, key_file: str, timeout: float = 20.0) -> TvReading:
    """Read the TV, never pairing: with no key for `ip` in `key_file` it connects to nothing and returns
    `not paired` (exit code 4), and with a key the TV refused at an earlier reading it connects to
    nothing and returns `key refused` (exit code 5) until `pair()` runs, so no prompt ever reaches the
    screen from a reading. Never hangs: each call gets `timeout`, the whole reading four times that. A
    TV that stalls on several keys runs the reading out of time; the keys read by then (Live Plus is
    first) are kept, and the ones never asked read as errors, which ingest does not store."""
    return _reading(ip, key_file, timeout, register=False)


def pair(ip: str, key_file: str, timeout: float = PAIR_TIMEOUT, manifest: str | None = None) -> TvReading:
    """Pair with the TV, then read it: the one call that may register, and so put the pairing prompt on
    the screen (with a key already stored the TV answers at once and this is the reading `read()` takes).
    `manifest` is `signed` (the library's) or `unsigned` (tvgw's read-only one); None means the manifest
    the stored key was made with while the TV still takes it (the CX's `signed` key is paired again with
    `signed`), and `unsigned` for a new pairing or after a refusal. The choice is recorded in the key
    store with the key, and a refusal on record is cleared when the TV answers.
    The key, with the library's manifest, is a full remote-control credential, so it is written under
    umask 077 and left 0600, readable by its owner (root) alone; the caller's umask is restored after.
    `timeout` per call is how long someone at the TV has to accept."""
    if manifest is not None and manifest not in lgkeys.MANIFESTS:
        raise ValueError(f"manifest {manifest!r}: expected one of {', '.join(lgkeys.MANIFESTS)}")
    old = os.umask(0o077)
    try:
        rec = lgkeys.record(key_file, ip)
        kind = manifest or (rec.manifest if rec is not None and not rec.refused else "unsigned")
        r = _reading(ip, key_file, timeout, register=True, manifest=kind)
        if r.reachable:
            lgkeys.paired(key_file, ip, kind)  # the TV took a key with this manifest: no refusal stands
    finally:
        os.umask(old)
    with contextlib.suppress(FileNotFoundError):  # the library never got as far as its storage
        os.chmod(key_file, 0o600)
    return r


def _reading(
    ip: str, key_file: str, timeout: float, register: bool, manifest: str | None = None
) -> TvReading:
    r = TvReading(False, error="TimeoutError")
    try:
        return asyncio.run(
            asyncio.wait_for(
                _read(ip, key_file, timeout, r, register=register, manifest=manifest), timeout * 4
            )
        )
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
PROBE_PORT = SSAP_PORT  # wss on 3001: this CX refuses ws on 3000 (section 14, F2), and newer sets hang on it
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
    async def connect(
        cls,
        host: str,
        port: int,
        ssl_ctx,
        frame_max: int = PROBE_FRAME_MAX,
        timeout: float = PROBE_IO_TIMEOUT,
    ) -> _WebSocket:
        """Open and upgrade within `timeout` (the connect, then the reply to the upgrade): a TV that
        accepts the connection and then says nothing, as a 2025 set does on its old port for minutes
        after power-on, is an error here, never a hang."""
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx, limit=1 << 16), timeout
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
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
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
    """`tvgw tvprobe`: the stored key and the manifest it was made with (the key store's row; the
    library's signed manifest for a key from before the row existed), wss with the TV's self-signed
    certificate, the carrier of TV_IF. 1 when it cannot start, 2 when the TV refused the key; a refusal
    on record from the hourly reading stops it before it connects."""

    if not os.path.exists(key_file):
        print(f"tvgw tvprobe: no key file at {key_file}; the probe never pairs (pair with sudo tvgw tv pair)")
        return 1
    key = asyncio.run(_stored_key(key_file, ip))
    if not key:
        print(f"tvgw tvprobe: no pairing for {ip} in {key_file}; the probe never pairs")
        return 1
    rec = lgkeys.record(key_file, ip)
    if rec is not None and rec.refused:
        when = time.strftime("%Y-%m-%d", time.localtime(rec.refused_at))
        print(f"tvgw tvprobe: the TV refused the key on {when} ({rec.refused_why})")
        print("tvgw tvprobe: pair again with sudo tvgw tv pair; the probe never does")
        return 2
    try:
        manifest = manifest_for(rec.manifest if rec else "signed")
    except ImportError as e:  # pragma: no cover - depends on the install
        print(f"tvgw tvprobe: bscpylgtv is not installed ({e})")
        return 1
    cfg = ProbeConfig(ip, ssl_ctx=_ssl_context(), client_key=key, manifest=manifest, seconds=hours * 3600)
    log = ProbeLog(out)
    try:
        rc = asyncio.run(probe(cfg, log, carrier(tv_if)))
    finally:
        log.close()
    if rc == 2:
        lgkeys.refused(key_file, ip, "the probe's registration was refused")
    print(f"tvgw tvprobe: {'stopped: the TV refused the key' if rc == 2 else 'done'}; events in {out}")
    return rc
