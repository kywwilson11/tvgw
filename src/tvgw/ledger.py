"""The change ledger and the hour classifier (design decision 48).

The hourly judge asks "did streaming bytes per TV hour fall?" and blames the newest machine rule for
any yes. On this gateway a 24-hour trial always holds other changes: AdGuard restarts, applies from
the NetworkManager dispatcher, deploys, a VPN reconnect, a link flap, an evening on an HDMI input.
This module records them and says, for each clock hour, whether the hour can be used to judge a rule:

- **The ledger** (`changes`): one append-only row per change, from four writers. `tvgw-apply`, the
  dispatcher, `install.sh` (through `tvgw changes --note-deploy`) and the owner's site-rule commands
  (`tvgw allow` and the rest) append one line each to
  `<STATE_DIR>/changes.spool`, a file and not the store, because they are shell or run while the
  store may be locked; the hourly ingest loads it exactly once. The sampler below adds the events it
  derives from consecutive samples, and the ingest copies the machine rules' adds and verdicts from
  `auto_rules`. No row carries an address.
- **The sampler** (`gw_samples`): one row every 10 minutes from `tvgw verify --record`. Nine of the
  sources a judge needs are cumulative counters (boot id, carrier changes, AdGuard's InvocationID and
  NRestarts, conntrack's statistics, interface bytes, Wi-Fi station fields, the VPN state, filter
  file times), so a 10-minute sample loses no event, only its exact time: an event derived from two
  samples carries `t_precision` 600. Every source is optional: a missing tool is a NULL, never a
  failure of `verify`.
- **The classifier**: `classify_hour(conn, h)` labels the hour `off`, `no_demand`, `confounded` or
  `clean` from the readings, the expected-category starts and lookups, the class-A changes and the
  samples over [h - 600 s, h + 3600 s). One function feeds judge v2, the placebo calibration, the
  brief's "Changes in effect" and the analyst's counts.

Everything that touches the system (files, commands, the clock) is a parameter, so the logic is
tested without a gateway.
"""

from __future__ import annotations

import bisect
import contextlib
import dataclasses
import hashlib
import hmac
import itertools
import json
import math
import os
import re
import shutil
import sqlite3
import statistics
import subprocess
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from tvgw import activity, db, minimize, queries
from tvgw.config import Settings
from tvgw.logtail import TailState, renamed_away
from tvgw.profile import Profile

SPOOL = "changes.spool"  # under STATE_DIR; tvgw-apply, the dispatcher and install.sh append to it
SPOOL_ROTATE = 256 * 1024  # bytes: a spool read whole and larger than this is renamed to .1
SAMPLE_PRECISION = 600.0  # seconds: an event seen between two samples happened in the 10 minutes before
LEAD = 600  # seconds before the hour the classifier also looks at (a restart at :55 hurts the next hour)
OWN_RESTART = 300  # seconds after a rule's apply in which its own AdGuard restart is excused
PIA_OK = "Connected"
CT_PRESSURE = 0.75  # conntrack count over this share of its max: new connections may be refused
WIFI_DROP_DB = 6.0  # signal this far below its 14-day median, in 2 samples of the hour: supply fell
WIFI_DAYS = 14
WIFI_MIN_HISTORY = 12  # samples before a median means anything
# the link rate counts only where it falls short of what the TV pulled: in WIFI_LOW_SAMPLES samples of
# the hour, under both its 14-day WIFI_RX_PCTL quantile and WIFI_HEADROOM times the hour's peak TV download
# rate; a jump of `tx failed` over WIFI_TX_FAILED in one sample interval counts as one such sample. The
# rate renegotiates all day (433 to 180 Mbit/s with the signal steady) while the TV needs about 6, so the
# old test (two samples under the 10th percentile) flagged about 15% of hours by construction
WIFI_LOW_SAMPLES = 3
WIFI_RX_PCTL = 0.02
WIFI_HEADROOM = 4
WIFI_TX_FAILED = 50
CONTENTION = 0.5  # the Pi's own upload above this share of the hour's peak TV download rate
CONTENTION_FLOOR = 125_000  # bytes per second (1 Mbit/s): below it the Pi's upload contends with nothing
# an ingest run reports the events conntrack lost since the run before, an hour earlier: a warning in
# a run within two hours after an hour began may be about that hour
LOST_SPAN = 2 * 3600
MIN_STARTS = 3  # expected-category flow starts in the hour that make it a demand hour
MIN_LOOKUPS = 3  # expected-category lookups (allowed) in the hour that make it a demand hour
# apps whose hour carries no streaming by construction: the launcher (autoblock.HOME_APPS) and the TV's
# own inputs. The input ids are those LG integrations use; whether this CX reports them so is checked
# with `tvgw sql "select app, count(*) from tvstate group by 1"` (section 16, open question 2)
NO_DEMAND_APPS = ("", "com.webos.app.home", "com.webos.app.launcher")
NO_DEMAND_PREFIXES = ("com.webos.app.hdmi", "com.webos.app.livetv", "com.webos.app.externalinput")
VPN_IFS = ("tun0", "wgpia0")  # PIA's OpenVPN and WireGuard interfaces, looked for in this order
PIACTL = ("/usr/local/bin/piactl", "/opt/piavpn/bin/piactl")
CMD_TIMEOUT = 5  # seconds per sampler command: a hung piactl must not hold verify up
CLASSES = ("off", "no_demand", "confounded", "clean")
_FIELD = re.compile(r"[A-Za-z0-9_.:+-]{1,64}")
_WORD = re.compile(r"[A-Za-z][A-Za-z ]{0,31}")
_FILTER_ID = re.compile(r"[0-9]{1,20}")

# kind -> (effect class, controllable, the label the brief and the classifier's reasons use). Class A
# can move the TV's metrics and is a confounder; class B is logged and cannot.
KINDS: dict[str, tuple[str, int, str]] = {
    "machine_rule_add": ("A", 1, "machine rule added"),
    "machine_rule_reverted": ("A", 1, "machine rule reverted"),
    "machine_rule_passed": ("B", 1, "machine rule passed"),
    "code_deploy": ("A", 1, "deploy"),
    "apply": ("B", 1, "apply"),  # class A when it changed routing (see _spool_row)
    "adguard_restart": ("A", 0, "AdGuard restart"),
    "reboot": ("A", 0, "gateway reboot"),
    "tv_flap": ("A", 0, "TV link flap"),
    "wan_flap": ("A", 0, "uplink flap"),
    "vpn_flap": ("A", 0, "VPN link flap"),
    "vpn_gone": ("A", 0, "VPN interface gone"),
    "vpn_back": ("A", 0, "VPN interface back"),
    "pia_down": ("A", 0, "PIA not connected"),
    "ct_drop": ("A", 0, "conntrack drops"),
    "ct_pressure": ("A", 0, "conntrack pressure"),
    "list_refresh": ("B", 0, "list refresh"),
    "list_removed": ("B", 0, "list removed"),
    "tv_link_up": ("A", 0, "TV link up"),
    "tv_link_down": ("A", 0, "TV link down"),
    "wan_link_up": ("A", 0, "uplink up"),
    "wan_link_down": ("A", 0, "uplink down"),
    "vpn_up": ("A", 0, "VPN up"),
    "vpn_down": ("A", 0, "VPN down"),
    "dhcp_change": ("B", 0, "DHCP change"),
    "dispatcher_event": ("B", 0, "interface event"),
    # (plain) from the sampler's salted tag of the uplink's address and router: no address is kept
    "wan_addr_change": ("A", 0, "uplink address changed"),
    "wan_gw_change": ("A", 0, "home router changed"),
    # (site rules) `tvgw allow`, `block`, `unallow` or `unblock` took: what the TV may reach changed
    "owner_rule_change": ("A", 1, "owner rule changed"),
}
GROUPS = {  # the brief's rows, by where the change acts
    "Gateway": (
        "machine_rule_add", "machine_rule_reverted", "machine_rule_passed", "code_deploy", "apply",
        "adguard_restart", "reboot", "list_refresh", "list_removed", "dhcp_change", "dispatcher_event",
        "owner_rule_change",
    ),
    "Uplink": ("wan_flap", "wan_link_up", "wan_link_down", "wan_addr_change", "wan_gw_change", "vpn_flap",
               "vpn_gone", "vpn_back", "vpn_up", "vpn_down", "pia_down"),
    "TV path": ("tv_flap", "tv_link_up", "tv_link_down", "ct_drop", "ct_pressure"),
}  # fmt: skip
METRIC_FILES = ("ingest.py", "tshark.py", "queries.py", "names.py", "clienthello.py")  # the judged metric
# (plain) a connection the kernel destroyed with its timer still running was cut early; its cause is the
# nearest class-A change within max(CUT_NEAR, the change's t_precision) seconds before the time the change
# was seen, or CUT_NEAR after it (after its end, for one with an end). The kinds that end connections by
# themselves come before every other kind, so the apply that reacted to an address change is not its
# cause; among them the nearest wins, and this order settles a tie
CUT_NEAR = 30
CUT_CAUSES = (
    "reboot", "wan_addr_change", "wan_gw_change", "wan_link_down", "wan_flap", "tv_link_down", "tv_flap",
    "ct_pressure", "ct_drop", "vpn_gone", "vpn_down", "vpn_flap", "pia_down",
)  # fmt: skip
CUT_LABELS = {"apply": "apply that changed routing"}  # class-A kinds whose own label reads wrongly here
UNKNOWN_CAUSE = "cause unknown"
EXPLAIN_SLACK = 60  # seconds around a sample interval in which a precise line explains its uplink change
OWNER_VERBS = ("allow", "block", "unallow", "unblock")  # (site rules) the commands that write a spool line
WAN_SALT = "wan.salt"  # (plain) the uplink tag's key, beside decision 47's name keys, never in a backup
WAN_SALT_BYTES = 32


# ---- the spool -------------------------------------------------------------------------------------
def spool_path(s: Settings) -> str:
    return os.path.join(s.state_dir, SPOOL)


def append_spool(path: str, fields: Iterable[str], now: float | None = None) -> None:
    """One line, `<epoch>\\t<field>...`, appended with O_APPEND (lines from concurrent writers do not
    interleave) and created 0640. Fields that are not plain words are written as `?`."""
    line = "\t".join([f"{now if now is not None else time.time():.0f}", *(_clean_field(f) for f in fields)])
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        os.write(fd, (line + "\n").encode("utf-8"))
    finally:
        os.close(fd)


def _clean_field(v: str) -> str:
    return v if _FIELD.fullmatch(v or "") else "?"


def code_fingerprint(package_dir: str | None = None) -> tuple[str, str]:
    """(every module, the modules that define the judged metric) of the installed package, each as the
    first 12 hex digits of a SHA-256 over the sorted files: two deploys of the same code match, and a
    deploy that changed how flows are named or counted shows in the second."""
    root = package_dir or os.path.dirname(os.path.abspath(__file__))
    every, metric = hashlib.sha256(), hashlib.sha256()
    for name in sorted(os.listdir(root)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(root, name), "rb") as fh:
            data = fh.read()
        every.update(name.encode() + b"\0" + data)
        if name in METRIC_FILES:
            metric.update(name.encode() + b"\0" + data)
    return every.hexdigest()[:12], metric.hexdigest()[:12]


def note_deploy(s: Settings, version: str, now: float | None = None, package_dir: str | None = None) -> str:
    """The deploy line install.sh asks for: the version and both fingerprints. Returns the line's
    fields joined, for the installer's log."""
    code, metric = code_fingerprint(package_dir)
    fields = ["deploy", version.replace(" ", "_"), code, metric]
    append_spool(spool_path(s), fields, now)
    return " ".join(fields)


def _role(iface: str, s: Settings) -> str:
    if iface == s.tv_if:
        return "tv"
    if iface == s.wan_if:
        return "wan"
    return "vpn"


@dataclasses.dataclass(frozen=True)
class Change:
    t: float
    source: str
    kind: str
    subject: str = ""
    detail: dict | None = None
    t_precision: float = 0.0
    t_end: float | None = None
    effect_class: str | None = None  # None: the kind's own class
    metric_affecting: str | None = None


def _spool_row(fields: list[str], s: Settings, last_deploy: dict | None) -> Change | None:
    """One spool line as a change, or None for a line this version cannot read."""
    try:
        t = float(fields[0])
    except (ValueError, IndexError):
        return None
    if not math.isfinite(t) or len(fields) < 2:
        return None
    source, rest = fields[1], [_clean_field(f) for f in fields[2:]]
    if source == "dispatcher" and len(rest) >= 2:
        iface, action = rest[0], rest[1]
        role = _role(iface, s)
        if action in ("up", "down"):
            kind = f"{role}_link_{action}" if role != "vpn" else f"vpn_{action}"
        elif action.startswith("dhcp"):
            kind = "dhcp_change"
        else:
            kind = "dispatcher_event"
        return Change(t, "dispatcher", kind, iface, {"action": action}, t_precision=1.0)
    if source == "apply" and len(rest) >= 2:
        caller, routing = rest[0], rest[1]
        cls = "A" if routing == "changed" else "B"
        return Change(t, "apply", "apply", caller, {"routing": routing}, t_precision=1.0, effect_class=cls)
    if source == "owner" and len(rest) >= 2 and rest[0] in OWNER_VERBS:  # (site rules) one line a change
        return Change(t, "owner", "owner_rule_change", rest[1], {"action": rest[0]}, t_precision=1.0)
    if source == "deploy" and len(rest) >= 3:
        version, code, metric = rest[0], rest[1], rest[2]
        changed = last_deploy is None or last_deploy.get("code") != code
        metric_changed = last_deploy is not None and last_deploy.get("metric") != metric
        return Change(
            t,
            "deploy",
            "code_deploy",
            version,
            {"code": code, "metric": metric, "code_changed": changed},
            t_precision=1.0,
            effect_class="A" if changed else "B",
            metric_affecting="naming" if metric_changed else None,
        )
    return None


def _last_deploy(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute(
        "SELECT detail FROM changes WHERE kind = 'code_deploy' ORDER BY t DESC LIMIT 1"
    ).fetchone()
    if not row:
        return None
    with contextlib.suppress(ValueError, TypeError):
        d = json.loads(row[0])
        return d if isinstance(d, dict) else None
    return None


def write(conn: sqlite3.Connection, changes: Iterable[Change]) -> int:
    """Insert the changes once each (the natural key is time, source, kind and subject); returns the
    rows that were new."""
    n = 0
    for c in changes:
        cls, controllable, _ = KINDS.get(c.kind, ("B", 0, c.kind))
        cur = conn.execute(
            "INSERT OR IGNORE INTO changes(t, t_end, t_precision, source, kind, subject, detail,"
            " controllable, effect_class, metric_affecting) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                c.t,
                c.t_end,
                c.t_precision,
                c.source,
                c.kind,
                c.subject or "",
                json.dumps(c.detail, sort_keys=True) if c.detail is not None else None,
                controllable,
                c.effect_class or cls,
                c.metric_affecting,
            ),
        )
        n += cur.rowcount
    return n


def load_spool(
    conn: sqlite3.Connection,
    s: Settings,
    tail: Callable[..., int],
    warn: Callable[[str], None],
) -> int:
    """Load the spool's new lines through the ingest's exactly-once tail (`ingest._tail`, passed in so
    rows and cursor commit together), then rename a large, fully read spool to `.1` so it cannot grow
    for ever: the writers open it by name on every line, so the next line starts a new file, and the
    tail reads whatever was still owed in the old one. Returns the rows that were new."""
    path = spool_path(s)
    cursor = conn.execute("SELECT inode FROM ingest_state WHERE source = 'changes'").fetchone()
    if not os.path.exists(path) and not renamed_away(path, TailState(inode=cursor[0] if cursor else None)):
        return 0  # nothing has written one since the last rotation: not a missing source
    unread = 0

    def insert(lines: list[str]) -> int:
        nonlocal unread
        n = 0
        for line in lines:
            fields = line.split("\t")
            # a deploy compares with the one before it, which may be a line of this same batch
            last = _last_deploy(conn) if fields[1:2] == ["deploy"] else None
            row = _spool_row(fields, s, last)
            if row is None:
                unread += 1
                continue
            n += write(conn, [row])
        return n

    n = tail(conn, "changes", path, insert, warn)
    if unread:
        warn(f"changes: {unread} spool line(s) this version cannot read were skipped")
    with contextlib.suppress(OSError):
        if os.path.getsize(path) > SPOOL_ROTATE:
            os.replace(path, path + ".1")
    return n


# ---- the sampler -------------------------------------------------------------------------------------
@dataclasses.dataclass
class Sample:
    """One 10-minute reading of the gateway's own counters; None where the source is missing."""

    t: float
    boot_id: str | None = None
    tv_cc: int | None = None
    wan_cc: int | None = None
    vpn_if: str | None = None
    vpn_present: int | None = None
    vpn_cc: int | None = None
    pia_state: str | None = None
    wlan_signal: float | None = None
    wlan_rx_mbps: float | None = None
    wlan_tx_mbps: float | None = None
    wlan_tx_failed: int | None = None
    wan_rx_bytes: int | None = None
    wan_tx_bytes: int | None = None
    tv_rx_bytes: int | None = None
    tv_tx_bytes: int | None = None
    ct_count: int | None = None
    ct_max: int | None = None
    ct_drop: int | None = None
    ct_early_drop: int | None = None
    ct_insert_failed: int | None = None
    agh_invocation: str | None = None
    agh_nrestarts: int | None = None
    filter_mtimes: str | None = None  # JSON {filter id: [mtime, size]}
    # (plain) `<salt id>.<address tag>.<router tag>`: keyed HMACs of WAN_IF's address and its router, so a
    # change shows and no address is stored (wan_addr_tag()); None without an address or the key
    wan_addr_tag: str | None = None


SAMPLE_COLUMNS = tuple(f.name for f in dataclasses.fields(Sample))


def run_short(cmd: list[str]) -> str:
    """stdout of a sampler command, '' when it fails, is missing or takes over CMD_TIMEOUT seconds."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=CMD_TIMEOUT
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _int(text: str | None) -> int | None:
    try:
        return int((text or "").strip())
    except ValueError:
        return None


def _float(text: str) -> float | None:
    m = re.search(r"-?\d+(?:\.\d+)?", text)
    return float(m.group()) if m else None


def parse_station_dump(text: str) -> dict[str, float | int | None]:
    """The four fields the classifier uses from `iw dev <if> station dump`, of the first station (a
    client has one, its access point). The `Station <address>` line is never read: no address is kept."""
    out: dict[str, float | int | None] = {"signal": None, "rx": None, "tx": None, "tx_failed": None}
    seen = 0
    for line in text.splitlines():
        if line.startswith("Station "):
            seen += 1
            if seen > 1:
                break
            continue
        key, _, value = line.strip().partition(":")
        key = key.strip()
        if key == "signal" and out["signal"] is None:
            out["signal"] = _float(value)
        elif key == "rx bitrate":
            out["rx"] = _float(value)
        elif key == "tx bitrate":
            out["tx"] = _float(value)
        elif key == "tx failed":
            out["tx_failed"] = _int(value)
    return out


def parse_conntrack_stats(text: str) -> tuple[int, int, int] | None:
    """(drop, early_drop, insert_failed) summed over the CPUs of `conntrack -S`, or None."""
    totals = {"drop": 0, "early_drop": 0, "insert_failed": 0}
    seen = False
    for key, value in re.findall(r"\b(drop|early_drop|insert_failed)=(\d+)", text):
        totals[key] += int(value)
        seen = True
    return (totals["drop"], totals["early_drop"], totals["insert_failed"]) if seen else None


_INET = re.compile(r"\binet (\d{1,3}(?:\.\d{1,3}){3})/\d{1,2}\b")
_VIA = re.compile(r"^default via (\d{1,3}(?:\.\d{1,3}){3})\b", re.M)


def parse_inet(text: str) -> str | None:
    """(plain) The first IPv4 address of `ip -4 -o addr show dev <if> scope global`."""
    m = _INET.search(text)
    return m.group(1) if m else None


def parse_default_via(text: str) -> str | None:
    """(plain) The router of the first default route of `ip -4 route show default dev <if>`."""
    m = _VIA.search(text)
    return m.group(1) if m else None


def wan_salt_path(s: Settings) -> str:
    return os.path.join(minimize.key_dir(s.state_dir), WAN_SALT)


def wan_salt(s: Settings) -> bytes | None:
    """(plain) The uplink tag's key: read, or made once, 32 random bytes root-only in the name-key
    directory (0700), which `tvgw backup` never copies and `tvgw forget` deletes with the samples. None
    when it cannot be read or made (not root): the tag is then not taken, never taken unkeyed."""
    path = wan_salt_path(s)
    try:
        with open(path, "rb") as fh:
            key = fh.read()
        return key if len(key) == WAN_SALT_BYTES else None
    except FileNotFoundError:
        pass
    except OSError:
        return None
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return wan_salt(s)  # another sampler made it first
    except OSError:
        return None
    key = os.urandom(WAN_SALT_BYTES)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return key


def wan_addr_tag(salt: bytes, address: str, router: str | None) -> str:
    """(plain) `<salt id>.<address tag>.<router tag>` (`-` for no router): two samples' tags differ in a
    part exactly when that part changed, and the salt id keeps tags made with different keys (a store
    restored from a backup, a new key) from ever being compared."""

    def tag(kind: bytes, value: str) -> str:
        return hmac.new(salt, kind + b"\0" + value.encode("ascii"), hashlib.sha256).hexdigest()[:8]

    sid = hashlib.sha256(salt).hexdigest()[:4]
    return f"{sid}.{tag(b'addr', address)}.{tag(b'router', router) if router else '-'}"


def _tag_parts(tag: str | None) -> tuple[str, str, str] | None:
    parts = (tag or "").split(".")
    return (parts[0], parts[1], parts[2]) if len(parts) == 3 and all(parts) else None


def parse_systemctl_show(text: str) -> tuple[str | None, int | None]:
    """(InvocationID, NRestarts) from `systemctl show -p InvocationID -p NRestarts`."""
    props = dict(line.partition("=")[::2] for line in text.splitlines() if "=" in line)
    inv = props.get("InvocationID", "").strip()
    return (inv if re.fullmatch(r"[0-9a-f]{32}", inv) else None), _int(props.get("NRestarts"))


def sample(
    s: Settings,
    run: Callable[[list[str]], str] = run_short,
    read: Callable[[str], str | None] = read_text,
    exists: Callable[[str], bool] = os.path.exists,
    which: Callable[[str], str | None] = shutil.which,
    listdir: Callable[[str], list[str]] = os.listdir,
    stat: Callable[[str], os.stat_result] = os.stat,
    now: float | None = None,
    salt: Callable[[], bytes | None] | None = None,
) -> Sample:
    """Read every source once. Each one is optional: what is missing stays None. `salt` gives the
    uplink tag's key (`wan_salt()` by default)."""
    smp = Sample(t=now if now is not None else time.time())
    bid = (read("/proc/sys/kernel/random/boot_id") or "").strip()
    smp.boot_id = bid if re.fullmatch(r"[0-9a-f-]{36}", bid) else None

    def net(iface: str, leaf: str) -> int | None:
        return _int(read(f"/sys/class/net/{iface}/{leaf}"))

    smp.tv_cc, smp.wan_cc = net(s.tv_if, "carrier_changes"), net(s.wan_if, "carrier_changes")
    smp.tv_rx_bytes = net(s.tv_if, "statistics/rx_bytes")
    smp.tv_tx_bytes = net(s.tv_if, "statistics/tx_bytes")
    smp.wan_rx_bytes = net(s.wan_if, "statistics/rx_bytes")
    smp.wan_tx_bytes = net(s.wan_if, "statistics/tx_bytes")
    # (events) a tunnel VPN_IF names is looked for first; auto and none name none
    named = getattr(s, "vpn_if", "") or ""
    wanted = ((named,) if named not in ("", "auto", "none") else ()) + VPN_IFS
    present = next((x for x in wanted if exists(f"/sys/class/net/{x}")), None)
    smp.vpn_if, smp.vpn_present = present or VPN_IFS[0], int(present is not None)
    if present:
        smp.vpn_cc = net(present, "carrier_changes")
    piactl = which("piactl") or next((p for p in PIACTL if exists(p)), None)
    if piactl:
        state = run([piactl, "get", "connectionstate"]).strip().splitlines()
        if state and _WORD.fullmatch(state[0].strip()):
            smp.pia_state = state[0].strip()
    iw = which("iw")
    if iw and exists(f"/sys/class/net/{s.wan_if}/wireless"):
        st = parse_station_dump(run([iw, "dev", s.wan_if, "station", "dump"]))
        smp.wlan_signal, smp.wlan_rx_mbps, smp.wlan_tx_mbps = st["signal"], st["rx"], st["tx"]
        smp.wlan_tx_failed = st["tx_failed"]  # type: ignore[assignment]
    smp.ct_count = _int(read("/proc/sys/net/netfilter/nf_conntrack_count"))
    smp.ct_max = _int(read("/proc/sys/net/netfilter/nf_conntrack_max"))
    ct = which("conntrack")
    if ct and (stats := parse_conntrack_stats(run([ct, "-S"]))):
        smp.ct_drop, smp.ct_early_drop, smp.ct_insert_failed = stats
    if which("systemctl"):
        smp.agh_invocation, smp.agh_nrestarts = parse_systemctl_show(
            run(["systemctl", "show", "AdGuardHome", "-p", "InvocationID", "-p", "NRestarts"])
        )
    filters = os.path.join(os.path.dirname(s.adguard_yaml), "data", "filters")
    with contextlib.suppress(OSError):
        times = {}
        for name in sorted(listdir(filters)):
            stem, ext = os.path.splitext(name)
            if ext == ".txt" and _FILTER_ID.fullmatch(stem):
                st_ = stat(os.path.join(filters, name))
                times[stem] = [int(st_.st_mtime), int(st_.st_size)]
        smp.filter_mtimes = json.dumps(times, sort_keys=True)
    ip = which("ip")  # (plain) the uplink's address and router, kept only as the keyed tag
    if ip:
        address = parse_inet(run([ip, "-4", "-o", "addr", "show", "dev", s.wan_if, "scope", "global"]))
        key = (salt or (lambda: wan_salt(s)))() if address else None
        if address and key:
            router = parse_default_via(run([ip, "-4", "route", "show", "default", "dev", s.wan_if]))
            smp.wan_addr_tag = wan_addr_tag(key, address, router)
    return smp


def record_sample(conn: sqlite3.Connection, smp: Sample) -> None:
    conn.execute(
        f"INSERT OR REPLACE INTO gw_samples({', '.join(SAMPLE_COLUMNS)})"
        f" VALUES ({','.join('?' * len(SAMPLE_COLUMNS))})",
        dataclasses.astuple(smp),
    )
    conn.commit()


def _columns(conn: sqlite3.Connection) -> str:
    """The sample columns to select, NULL for one a store has not been migrated to yet (a read-only
    brief may open a store before any writer added the column)."""
    have = {r[1] for r in conn.execute("PRAGMA table_info(gw_samples)")}
    return ", ".join(c if c in have else f"NULL AS {c}" for c in SAMPLE_COLUMNS)


def samples(conn: sqlite3.Connection, a: float, b: float) -> list[Sample]:
    rows = conn.execute(
        f"SELECT {_columns(conn)} FROM gw_samples WHERE t >= ? AND t < ? ORDER BY t", (a, b)
    ).fetchall()
    return [Sample(*r) for r in rows]


# ---- events from consecutive samples ---------------------------------------------------------------------
def _delta(a: int | None, b: int | None) -> int:
    """A counter's rise between two samples; 0 when either is missing or it went down (a reset)."""
    return b - a if a is not None and b is not None and b > a else 0


def derive(prev: Sample, cur: Sample, s: Settings) -> list[Change]:
    """The changes two consecutive samples show. Counters reset at a reboot, so a changed boot id is
    the one event of that pair."""
    p = max(SAMPLE_PRECISION, cur.t - prev.t)

    def ev(kind: str, subject: str, detail: dict | None = None) -> Change:
        return Change(cur.t, "sampler", kind, subject, detail, t_precision=p)

    if prev.boot_id and cur.boot_id and prev.boot_id != cur.boot_id:
        return [ev("reboot", "gateway")]
    out = []
    for kind, subject, a, b in (
        ("tv_flap", s.tv_if, prev.tv_cc, cur.tv_cc),
        ("wan_flap", s.wan_if, prev.wan_cc, cur.wan_cc),
    ):
        if d := _delta(a, b):
            out.append(ev(kind, subject, {"changes": d}))
    if prev.vpn_present == 1 and cur.vpn_present == 0:
        out.append(ev("vpn_gone", prev.vpn_if or "vpn"))
    elif prev.vpn_present == 0 and cur.vpn_present == 1:
        out.append(ev("vpn_back", cur.vpn_if or "vpn"))
    elif prev.vpn_if == cur.vpn_if and (d := _delta(prev.vpn_cc, cur.vpn_cc)):
        out.append(ev("vpn_flap", cur.vpn_if or "vpn", {"changes": d}))
    drops = {
        "drop": _delta(prev.ct_drop, cur.ct_drop),
        "early_drop": _delta(prev.ct_early_drop, cur.ct_early_drop),
        "insert_failed": _delta(prev.ct_insert_failed, cur.ct_insert_failed),
    }
    if any(drops.values()):
        out.append(ev("ct_drop", "conntrack", drops))

    def pressed(x: Sample) -> bool:
        return bool(x.ct_count is not None and x.ct_max and x.ct_count > CT_PRESSURE * x.ct_max)

    if pressed(cur) and not pressed(prev):
        out.append(ev("ct_pressure", "conntrack", {"pct": round(100 * cur.ct_count / cur.ct_max)}))  # type: ignore[operator]
    if prev.agh_invocation and cur.agh_invocation and prev.agh_invocation != cur.agh_invocation:
        automatic = _delta(prev.agh_nrestarts, cur.agh_nrestarts)  # NRestarts counts systemd's own restarts
        out.append(ev("adguard_restart", "AdGuardHome", {"automatic": automatic}))
    before, after = _filters(prev.filter_mtimes), _filters(cur.filter_mtimes)
    if before is not None and after is not None:
        for fid, (mtime, size) in sorted(after.items()):
            if before.get(fid, [None])[0] != mtime:
                out.append(ev("list_refresh", fid, {"size": size}))
        for fid in sorted(set(before) - set(after)):
            out.append(ev("list_removed", fid))
    # (plain) the uplink's address or router moved: tags of the same key, compared part by part
    was, now_ = _tag_parts(prev.wan_addr_tag), _tag_parts(cur.wan_addr_tag)
    if was and now_ and was[0] == now_[0]:
        router = "-" not in (was[2], now_[2]) and was[2] != now_[2]
        if was[1] != now_[1]:
            out.append(ev("wan_addr_change", s.wan_if, {"router": "changed" if router else "same"}))
        elif router:
            out.append(ev("wan_gw_change", s.wan_if))
    return out


def _explained(conn: sqlite3.Connection, c: Change) -> bool:
    """(plain) A sampler's uplink change that a writer with a precise time (the dispatcher's spool line)
    already recorded inside the sample interval, or up to EXPLAIN_SLACK seconds either side of it (the
    dispatcher runs a moment after the address moves, and a sample can fall in between)."""
    lo, hi = c.t - c.t_precision - EXPLAIN_SLACK, c.t + EXPLAIN_SLACK
    return bool(
        conn.execute(
            "SELECT 1 FROM changes WHERE kind = ? AND source != 'sampler' AND t >= ? AND t <= ? LIMIT 1",
            (c.kind, lo, hi),
        ).fetchone()
    )


def _filters(raw: str | None) -> dict[str, list[int]] | None:
    if raw is None:
        return None
    try:
        d = json.loads(raw)
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def _meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def derive_all(conn: sqlite3.Connection, s: Settings) -> int:
    """Derive the changes of every sample since the last run (meta `ledger_samples_t`), and close a
    PIA outage once a sample reads Connected again: an outage is one `pia_down` row with its start
    (the first sample not Connected) and its end, written when it ends, so the table stays append-only.
    The classifier reads an outage still open from the samples themselves."""
    raw = _meta(conn, "ledger_samples_t")
    wm = float(raw) if raw else None
    new = [x for x in samples(conn, wm if wm is not None else -math.inf, math.inf) if wm is None or x.t > wm]
    if not new:
        return 0
    prev = (
        conn.execute(
            f"SELECT {_columns(conn)} FROM gw_samples WHERE t <= ? ORDER BY t DESC LIMIT 1", (wm,)
        ).fetchone()
        if wm is not None
        else None
    )
    chain = ([Sample(*prev)] if prev else []) + new
    out: list[Change] = []
    for a, b in itertools.pairwise(chain):
        out += derive(a, b, s)
    uplink = ("wan_addr_change", "wan_gw_change")
    out = [c for c in out if c.kind not in uplink or not _explained(conn, c)]
    try:
        open_ = json.loads(_meta(conn, "ledger_pia_open") or "null")
    except ValueError:
        open_ = None
    for cur in new:
        if cur.pia_state is None:
            continue
        if cur.pia_state != PIA_OK:
            if open_ is None:
                open_ = {"t": cur.t, "states": [cur.pia_state]}
            elif cur.pia_state not in open_["states"]:
                open_["states"].append(cur.pia_state)
        elif open_ is not None:
            out.append(
                Change(open_["t"], "sampler", "pia_down", open_["states"][0], {"states": open_["states"]},
                       t_precision=SAMPLE_PRECISION, t_end=cur.t)
            )  # fmt: skip
            open_ = None
    n = write(conn, out)
    db.set_meta(conn, "ledger_samples_t", str(new[-1].t))
    db.set_meta(conn, "ledger_pia_open", json.dumps(open_))
    return n


def from_auto_rules(conn: sqlite3.Connection) -> int:
    """The machine rules' adds and verdicts as ledger rows. `auto_rules` keeps one row per rule, which a
    second trial replaces; the ledger keeps both trials, because rows already copied stay."""
    out = []
    for rule, added, verdict, decided in conn.execute(
        "SELECT rule, added_t, verdict, decided_t FROM auto_rules"
    ).fetchall():
        out.append(Change(added, "autoblock", "machine_rule_add", rule))
        if verdict in ("reverted", "passed") and decided is not None:
            out.append(Change(decided, "autoblock", f"machine_rule_{verdict}", rule))
    return write(conn, out)


def ingest(
    conn: sqlite3.Connection,
    s: Settings,
    tail: Callable[..., int],
    warn: Callable[[str], None] = print,
) -> int:
    """The hourly ingest's ledger step: the spool, the samples, the machine rules."""
    if s.ledger != "on":
        return 0
    n = load_spool(conn, s, tail, warn)
    n += derive_all(conn, s)
    n += from_auto_rules(conn)
    return n


# ---- the hour classifier -----------------------------------------------------------------------------------
def no_demand_app(app: str | None) -> bool:
    a = app or ""
    return a in NO_DEMAND_APPS or a.startswith(NO_DEMAND_PREFIXES)


_PCAP_UTC = re.compile(r"^tv(?:hdr)?_(\d{14})_\d+\.pcap$")
_PCAP_LOCAL = re.compile(r"^tv-(\d{8})-(\d{4})\.pcap$")


def pcap_hour(name: str) -> int | None:
    """The clock hour (epoch, hour-aligned) a capture file starts in, from its name: dumpcap's
    `tv_<UTC YYYYmmddHHMMSS>_<n>.pcap` (and `tvhdr_`) or tcpdump's local `tv-YYYYMMDD-HHMM.pcap`."""
    if m := _PCAP_UTC.match(name):
        t = datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=UTC).timestamp()
    elif m := _PCAP_LOCAL.match(name):
        t = datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M").timestamp()
    else:
        return None
    return int(t // 3600) * 3600


@dataclasses.dataclass(frozen=True)
class HourFacts:
    on: bool
    app: str | None
    starts: int
    lookups: int
    bytes_end: float  # expected-category bytes down of flows that ended in the hour
    bytes_prorated: float  # the same, each flow's bytes spread over its lifetime
    readings_active: int  # 'Active' readings: the TV hours autoblock.streaming_rate counts
    # (activity) a streaming interval of the TV port's counters overlaps the hour, counted only on a
    # gateway whose TV gives no readings at all (activity.streaming_hours)
    streaming: bool = False


class Classifier:
    """The store's facts over [a, b), loaded once, so that a day of hours (the brief) or 60 days (the
    calibration) costs one pass over the flows rather than one per hour."""

    def __init__(self, conn: sqlite3.Connection, prof: Profile | None, a: float, b: float):
        self.conn = conn
        self.a, self.b = int(a // 3600) * 3600 - 3600, math.ceil(b / 3600) * 3600 + 3600
        cats = tuple(prof.expected_categories) if prof else ()
        self.cats = cats or ("Streaming",)
        self._load()

    def _load(self) -> None:
        conn, a, b, cats = self.conn, self.a, self.b, self.cats
        marks = ",".join("?" * len(cats))
        self.expected = {
            n for (n,) in conn.execute(f"SELECT name FROM hosts WHERE category IN ({marks})", cats)
        }
        self.readings: dict[int, list[tuple[float, str, str | None]]] = {}
        for t, power, app in conn.execute(
            "SELECT t, power, app FROM tvstate WHERE t >= ? AND t < ? ORDER BY t", (a, b)
        ):
            self.readings.setdefault(int(t // 3600) * 3600, []).append((t, power or "", app))
        # (activity) a TV that gives no readings (a Samsung unpaired, a Roku, a Vizio): its port's counters
        # say which hours it streamed. On a TV with readings they stay authoritative, so nothing changes
        self.unread = conn.execute("SELECT 1 FROM tvstate LIMIT 1").fetchone() is None
        self.streamed = activity.streaming_hours(conn, a, b) if self.unread else set()
        self.starts: dict[int, int] = {}
        self.bytes_end: dict[int, float] = {}
        self.bytes_pro: dict[int, float] = {}
        rows = conn.execute(
            f"""SELECT f.t_start, f.t_end, COALESCE(f.bytes_down, 0), {queries.FLOW_NAME} FROM flows f
                WHERE f.t_end >= ? AND COALESCE(f.t_start, f.t_end) < ?""",
            (a, b),
        )
        for t0, t1, down, name in rows:
            if name not in self.expected:
                continue
            start = t0 if t0 is not None else t1
            if a <= start < b:
                h = int(start // 3600) * 3600
                self.starts[h] = self.starts.get(h, 0) + 1
            if a <= t1 < b:
                h = int(t1 // 3600) * 3600
                self.bytes_end[h] = self.bytes_end.get(h, 0) + down
            span = max(t1 - start, 0.0)
            if span <= 0:
                h = int(t1 // 3600) * 3600
                self.bytes_pro[h] = self.bytes_pro.get(h, 0) + down
                continue
            h = int(start // 3600) * 3600
            while h < t1:
                part = (min(h + 3600, t1) - max(h, start)) / span
                if a <= h < b:
                    self.bytes_pro[h] = self.bytes_pro.get(h, 0) + down * part
                h += 3600
        self.lookups = dict(
            conn.execute(
                f"""SELECT CAST(d.t / 3600 AS INTEGER) * 3600, COUNT(*) FROM dns d
                    JOIN hosts ON hosts.name = d.qname WHERE d.t >= ? AND d.t < ? AND d.blocked = 0
                    AND hosts.category IN ({marks}) GROUP BY 1""",
                (a, b, *cats),
            )
        )
        self.changes = [
            dict(zip(("t", "t_end", "p", "source", "kind", "subject"), r, strict=True))
            for r in conn.execute(
                "SELECT t, t_end, t_precision, source, kind, subject FROM changes WHERE effect_class = 'A'"
                " AND t < ? AND COALESCE(t_end, t) >= ? ORDER BY t",
                (b + SAMPLE_PRECISION, a - LEAD),
            )
        ]
        self.samples = samples(conn, a - WIFI_DAYS * 86400, b)
        self._sample_t = [x.t for x in self.samples]
        self._wifi_floor: dict[int, tuple[float | None, float | None]] = {}
        self.capture_gaps = {
            h
            for (name,) in conn.execute(
                "SELECT name FROM pcaps_done WHERE error IS NULL AND COALESCE(tls_rows, 0) = 0"
                " AND COALESCE(syn443_rows, 0) > 0"
            )
            if (h := pcap_hour(name)) is not None and a <= h < b
        }
        # (plain) connections cut early: the kernel destroyed them with their timer still running
        self.cuts = [
            t
            for (t,) in conn.execute(
                "SELECT t_end FROM flows WHERE state = 'ESTABLISHED' AND timeout_left IS NOT NULL"
                " AND t_end >= ? AND t_end < ? ORDER BY t_end",
                (a, b),
            )
        ]
        self.broken: dict[int, int] = {}
        for t in self.cuts:
            h = int(t // 3600) * 3600
            self.broken[h] = self.broken.get(h, 0) + 1
        self.lost_runs = [
            t
            for t, raw in conn.execute(
                "SELECT t, warnings FROM ingest_runs WHERE t >= ? AND t < ?", (a, b + queries.STALE)
            )
            if "lost events" in (raw or "")
        ]

    def facts(self, h: int) -> HourFacts:
        rd = self.readings.get(h, [])
        awake = [r for r in rd if r[1] in queries.AWAKE]
        streamed = h in self.streamed
        return HourFacts(
            on=bool(awake) or streamed,
            app=awake[-1][2] if awake else None,
            starts=self.starts.get(h, 0),
            lookups=self.lookups.get(h, 0),
            bytes_end=self.bytes_end.get(h, 0.0),
            bytes_prorated=self.bytes_pro.get(h, 0.0),
            readings_active=sum(1 for r in rd if r[1] == "Active"),
            streaming=streamed,
        )

    def confounders(self, h: int, trial: dict | None = None) -> list[str]:
        """Why the hour cannot be judged, as short labels; empty when nothing is known against it."""
        a, b = h - LEAD, h + 3600
        found: list[str] = []
        for c in self.changes:
            seen, p = c["t"], c["p"] or 0.0
            end = c["t_end"] if c["t_end"] is not None else seen
            if not (seen - p < b and end >= a):
                continue
            if trial and c["kind"] == "machine_rule_add" and c["subject"] == trial.get("rule"):
                continue  # the rule under trial is what is being judged
            if (
                trial
                and c["kind"] == "adguard_restart"
                and seen >= trial["added_t"]
                and seen - p <= trial["added_t"] + OWN_RESTART
            ):
                continue  # its own apply's restart
            found.append(KINDS.get(c["kind"], ("A", 0, c["kind"]))[2])
        window = self._window(a, b)
        bad_pia = sorted({x.pia_state for x in window if x.pia_state and x.pia_state != PIA_OK})
        found += [f"PIA {state}" for state in bad_pia]
        if any(x.ct_count is not None and x.ct_max and x.ct_count > CT_PRESSURE * x.ct_max for x in window):
            found.append("conntrack pressure")
        if self._wifi_degraded(h, window):
            found.append("Wi-Fi degraded")
        if self._contended(window):
            found.append("uplink contention")
        if h in self.capture_gaps:
            found.append("capture named nothing")
        if self.broken.get(h):
            found.append("connections cut early")
        if any(h < t <= h + LOST_SPAN for t in self.lost_runs):
            found.append("conntrack lost events")
        return list(dict.fromkeys(found))

    def _window(self, a: float, b: float) -> list[Sample]:
        return self.samples[bisect.bisect_left(self._sample_t, a) : bisect.bisect_left(self._sample_t, b)]

    def _floors(self, h: int) -> tuple[float | None, float | None]:
        """(signal floor, rx bitrate floor) from the WIFI_DAYS before the day `h` falls in: the 14-day
        median less WIFI_DROP_DB, and the WIFI_RX_PCTL quantile. Kept per day, so 60 days of hours cost 60."""
        day = int(h // 86400) * 86400
        if day not in self._wifi_floor:
            history = self._window(day - WIFI_DAYS * 86400, day)
            sig = [x.wlan_signal for x in history if x.wlan_signal is not None]
            rx = [x.wlan_rx_mbps for x in history if x.wlan_rx_mbps is not None]
            self._wifi_floor[day] = (
                statistics.median(sig) - WIFI_DROP_DB if len(sig) >= WIFI_MIN_HISTORY else None,
                statistics.quantiles(rx, n=100)[round(WIFI_RX_PCTL * 100) - 1]
                if len(rx) >= WIFI_MIN_HISTORY
                else None,
            )
        return self._wifi_floor[day]

    def _wifi_degraded(self, h: int, window: list[Sample]) -> bool:
        """Supply fell: the signal in 2 samples under its floor, or (plain) the link rate where it mattered:
        WIFI_LOW_SAMPLES samples under both its floor and WIFI_HEADROOM times the hour's peak TV download,
        a `tx failed` jump over WIFI_TX_FAILED in an interval counting as one."""
        sig_floor, rx_floor = self._floors(h)
        low_sig = sum(
            1
            for x in window
            if sig_floor is not None and x.wlan_signal is not None and x.wlan_signal < sig_floor
        )
        if low_sig >= 2:
            return True
        need = WIFI_HEADROOM * self._pairs(window)[0] * 8 / 1e6  # Mbit/s
        # the low samples by their time: a sample whose rate fell short and that also ends an interval
        # with a `tx failed` jump is one low sample, not two
        low = {
            x.t
            for x in window
            if rx_floor is not None
            and x.wlan_rx_mbps is not None
            and x.wlan_rx_mbps < rx_floor
            and x.wlan_rx_mbps < need
        }
        low |= {
            c.t
            for p, c in self._intervals(window)
            if _delta(p.wlan_tx_failed, c.wlan_tx_failed) > WIFI_TX_FAILED
        }
        return len(low) >= WIFI_LOW_SAMPLES

    @staticmethod
    def _intervals(window: list[Sample]) -> list[tuple[Sample, Sample]]:
        """Consecutive samples of one boot, a positive time apart: the intervals a counter's rise means
        something over."""
        return [
            (p, c)
            for p, c in itertools.pairwise(window)
            if c.t - p.t > 0 and not (p.boot_id and c.boot_id and p.boot_id != c.boot_id)
        ]

    def _pairs(self, window: list[Sample]) -> tuple[float, list[float]]:
        """(the peak TV download rate, the gateway's own upload rate per interval), in bytes per second."""
        peak_tv, own = 0.0, []
        for p, c in self._intervals(window):
            dt = c.t - p.t
            peak_tv = max(peak_tv, _delta(p.tv_tx_bytes, c.tv_tx_bytes) / dt)
            own.append((_delta(p.wan_tx_bytes, c.wan_tx_bytes) - _delta(p.tv_rx_bytes, c.tv_rx_bytes)) / dt)
        return peak_tv, own

    def _contended(self, window: list[Sample]) -> bool:
        peak_tv, own = self._pairs(window)
        return any(u > CONTENTION_FLOOR and u > CONTENTION * peak_tv for u in own) if own else False

    def cause(self, t: float) -> tuple[str, float | None]:
        """(plain) Why a connection was cut early at `t`: (the label of the nearest class-A change that
        explains it, that change's time), or (UNKNOWN_CAUSE, None) with no change near. A change explains
        a cut from max(CUT_NEAR, its t_precision) seconds before the time it was seen to CUT_NEAR after
        it, or after its end. The kinds of CUT_CAUSES come before every other kind; among either the
        nearest wins, and at the same distance CUT_CAUSES' order, then the earlier change."""
        best: tuple | None = None
        for c in self.changes:
            p = c["p"] or 0.0
            seen, end = c["t"], c["t_end"] if c["t_end"] is not None else c["t"]
            if not (seen - max(CUT_NEAR, p) <= t <= end + CUT_NEAR):
                continue
            distance = 0.0 if seen - p <= t <= end else min(abs(t - (seen - p)), abs(t - end))
            rank = CUT_CAUSES.index(c["kind"]) if c["kind"] in CUT_CAUSES else len(CUT_CAUSES)
            key = (rank == len(CUT_CAUSES), distance, rank, seen)
            if best is None or key < best[0]:
                best = (key, c)
        if best is None:
            return UNKNOWN_CAUSE, None
        c = best[1]
        return CUT_LABELS.get(c["kind"]) or KINDS.get(c["kind"], ("A", 0, c["kind"]))[2], c["t"]

    def cut_early(self, a: float, b: float) -> dict:
        """(plain) The connections cut early in [a, b): how many, how many per cause, and the first cut
        of each cause (the time the brief prints)."""
        by: dict[str, int] = {}
        first: dict[str, float] = {}
        for t in self.cuts:
            if a <= t < b:
                label, _ = self.cause(t)
                by[label] = by.get(label, 0) + 1
                first.setdefault(label, t)
        return {"cut_early": sum(by.values()), "by_cause": by, "cut_first": first}

    def classify(self, h: int, trial: dict | None = None) -> tuple[str, list[str]]:
        """`off`, `no_demand`, `confounded` or `clean`, with the reasons."""
        f = self.facts(h)
        if not f.on:
            return "off", ["no reading says the TV was on"]
        demand = []
        if f.streaming:  # (activity) no readings: the port's counters saw a stream
            demand.append("streaming traffic")
        if not no_demand_app(f.app):
            demand.append("app in front")
        if f.starts >= MIN_STARTS:
            demand.append(f"{f.starts} expected starts")
        if f.lookups >= MIN_LOOKUPS:
            demand.append(f"{f.lookups} expected lookups")
        if not demand:
            return "no_demand", ["input or launcher in front" if f.app is not None else "nothing in front"]
        flags = self.confounders(h, trial)
        return ("confounded", flags) if flags else ("clean", demand)


def classify_hour(
    conn: sqlite3.Connection, h: float, prof: Profile | None = None, trial: dict | None = None
) -> tuple[str, list[str]]:
    """The class of the clock hour starting at `h` (rounded down to the hour) and the reasons: the
    one function the judge, the calibration, the brief and the pack share."""
    hh = int(h // 3600) * 3600
    return Classifier(conn, prof, hh, hh + 3600).classify(hh, trial)


def hours(a: float, b: float) -> list[int]:
    """The clock hours that start in [a, b)."""
    first = math.ceil(a / 3600) * 3600
    return list(range(first, int(b), 3600))


# ---- the brief's "Changes in effect" -------------------------------------------------------------------
def _hm(t: float, long: bool) -> str:
    return datetime.fromtimestamp(t).strftime("%m-%d %H:%M" if long else "%H:%M")


def section(
    conn: sqlite3.Connection, prof: Profile, a: float, b: float, now: float, k: int = 6
) -> dict | None:
    """What changed in [a, b) and how much of it a judge could use, as plain data; None when the window
    has no ledger rows, no samples and no machine rule on trial (a store from before the ledger)."""
    try:
        rows = conn.execute(
            "SELECT t, t_end, t_precision, source, kind, subject, effect_class, metric_affecting"
            " FROM changes WHERE t >= ? AND t < ? ORDER BY t",
            (a, b),
        ).fetchall()
        n_samples = conn.execute("SELECT COUNT(*) FROM gw_samples WHERE t >= ? AND t < ?", (a, b)).fetchone()[
            0
        ]
        trials = conn.execute(
            "SELECT rule, added_t, verdict FROM auto_rules WHERE added_t < ?"
            " AND (verdict IS NULL OR decided_t >= ?) ORDER BY added_t",
            (b, a),
        ).fetchall()
        shadow = _latest_shadow(conn)
    except sqlite3.OperationalError:  # a read-only reader of a store no writer has migrated yet
        return None
    if not rows and not n_samples and not trials:
        return None
    end = min(b, now)
    clf = Classifier(conn, prof, a, end)
    hour_rows = [
        {"h": h, "class": cls, "reasons": why}
        for h in hours(a, end - 3600 + 1)
        for cls, why in [clf.classify(h)]
    ]
    groups: dict[str, dict] = {}
    for t, t_end, p, source, kind, subject, ecls, metric in rows:
        group = next((g for g, kinds in GROUPS.items() if kind in kinds), "Gateway")
        g = groups.setdefault(group, {"events": [], "counts": []})
        label = KINDS.get(kind, ("B", 0, kind))[2]
        # an interface or a caller says what triggered it; a rule's text is in the trial line already
        trigger = subject if source in ("dispatcher", "apply") or kind == "pia_down" else ""
        if ecls == "A":
            g["events"].append({"t": t, "t_end": t_end, "kind": kind, "label": label, "trigger": trigger,
                                "approx": bool(p and p >= 60), "metric": metric})  # fmt: skip
        else:
            same = next((c for c in g["counts"] if c["kind"] == kind and c["trigger"] == trigger), None)
            if same:
                same["n"] += 1
            else:
                g["counts"].append({"kind": kind, "label": label, "trigger": trigger, "n": 1})
    window = samples(conn, a, b)
    ct_max = max((x.ct_max for x in window if x.ct_max), default=None)
    peak = max((x.ct_count / x.ct_max for x in window if x.ct_count is not None and x.ct_max), default=None)
    firmware = conn.execute(
        "SELECT value FROM tvsettings WHERE key = 'firmware' AND t < ? ORDER BY t DESC LIMIT 1", (b,)
    ).fetchone()
    fw_changes = conn.execute(
        "SELECT COUNT(*) FROM tvsettings WHERE key = 'firmware' AND t >= ? AND t < ?", (a, b)
    ).fetchone()[0]
    on_trial = []
    for rule, added, verdict in trials:
        v2 = shadow.get((rule, added))
        clean = (
            v2[2]
            if v2 and v2[2] is not None
            else sum(1 for x in hour_rows if x["h"] >= added and x["class"] == "clean")
        )
        need = v2[3] if v2 and v2[3] else k
        on_trial.append({
            "rule": rule, "added_t": added, "clean_hours": clean, "k": need,
            "v1": verdict or "watching", "v2": v2[0] if v2 else None, "v2_reason": v2[1] if v2 else None,
            "stalled": verdict in (None, "passed") and clean < need and now - added > CEILING / 2,
        })  # fmt: skip
    return {
        "window": [a, b],
        "on_trial": on_trial,
        "groups": groups,
        "tv_path": {
            "tv_flaps": sum(1 for r in rows if r[4] == "tv_flap"),
            "ct_max": ct_max,
            "ct_peak_pct": round(100 * peak) if peak is not None else None,
        },
        "tv": {"firmware": firmware[0] if firmware else None, "firmware_changes": fw_changes},
        "evidence": {
            "capture_gap_hours": sum(1 for h in clf.capture_gaps if a <= h < b),
            "lost_event_runs": sum(1 for t in clf.lost_runs if a < t <= b + LOST_SPAN - 3600),
            **clf.cut_early(a, b),  # (plain) cut_early, by_cause, cut_first
        },
        "hours": hour_rows,
        "hour_counts": {c: sum(1 for x in hour_rows if x["class"] == c) for c in CLASSES},
        "samples": n_samples,
        "red_lines": [
            f"machine rule {x['rule']} has spent more than half of judge v2's 14-day ceiling with"
            f" {x['clean_hours']} of {x['k']} clean TV hours"
            for x in on_trial
            if x["stalled"]
        ],
    }


CEILING = 14 * 86400  # judge v2's ceiling, which a stalled trial is measured against


def _latest_shadow(
    conn: sqlite3.Connection,
) -> dict[tuple[str, float], tuple[str, str, int | None, int | None]]:
    """(rule, added_t) -> judge v2's latest (verdict, reason, clean hours, K) in shadow."""
    rows = conn.execute(
        "SELECT rule, added_t, v2, v2_reason, clean_hours, k FROM judge_shadow s WHERE hour = (SELECT"
        " MAX(hour) FROM judge_shadow x WHERE x.rule = s.rule AND x.added_t = s.added_t)"
    ).fetchall()
    return {(r, a): (v, why or "", n, k) for r, a, v, why, n, k in rows}


def _event_text(e: dict, long: bool) -> str:
    when = _hm(e["t"], long) + (f"-{_hm(e['t_end'], long)}" if e.get("t_end") else "")
    trigger = f" ({e['trigger']})" if e["trigger"] else ""
    return (
        ("~" if e["approx"] else "")
        + f"{when} {e['label']}{trigger}"
        + (" (metric-affecting)" if e.get("metric") else "")
    )


def _cut_text(ev: dict, long: bool) -> str:
    """(plain) `connections cut early: 5 (uplink address changed 19:46)`: each cause with the time of its
    first cut, and with its count when there is more than one cause."""
    n, by, first = ev.get("cut_early", 0), ev.get("by_cause") or {}, ev.get("cut_first") or {}
    if not n:
        return "connections cut early: 0"
    causes = sorted(by, key=lambda label: first.get(label, 0))
    shown = [
        f"{label} {_hm(first[label], long)}" + (f" x{by[label]}" if len(by) > 1 else "")
        if label in first
        else label
        for label in causes
    ]
    return f"connections cut early: {n} ({'; '.join(shown)})"


def _count_text(c: dict) -> str:
    return c["label"] + (f" ({c['trigger']})" if c["trigger"] else "") + f" x{c['n']}"


def render(sec: dict) -> list[str]:
    """The section as the brief prints it: class-B changes as counts with their trigger, class-A
    changes with their times, and the hours a judge could use."""
    a, b = sec["window"]
    long = b - a > 90000
    out = [f"Changes in effect ({_hm(a, True)} .. {_hm(b, True)}; ~ marks a time known to 10 minutes):"]
    for x in sec["on_trial"]:
        v2 = f"; judge v2 (shadow): {x['v2']}" if x["v2"] else ""
        out.append(
            f"  On trial   {x['rule']}   added {_hm(x['added_t'], True)}; clean TV hours"
            f" {x['clean_hours']} of {x['k']} needed; judge: {x['v1']}{v2}"
        )
    for group in ("Gateway", "Uplink", "TV path"):
        g = sec["groups"].get(group, {"events": [], "counts": []})
        parts = [_event_text(e, long) for e in g["events"]]
        parts += [_count_text(c) for c in g["counts"]]
        if group == "TV path":
            tp = sec["tv_path"]
            peak = f", peak {tp['ct_peak_pct']}% full" if tp["ct_peak_pct"] is not None else ""
            ct = [f"conntrack: max {tp['ct_max']}{peak}"] if tp["ct_max"] else []
            parts = [f"TV link flaps: {tp['tv_flaps']}", *ct, *parts]
        if parts:
            out.append(f"  {group:<10} " + "   ".join(parts))
    tv = sec["tv"]
    n_fw = tv["firmware_changes"]
    fw = f"firmware changed {n_fw} time(s)" if n_fw else "firmware unchanged"
    out.append(f"  TV         {fw}" + (f" ({tv['firmware']})" if tv["firmware"] else ""))
    ev = sec["evidence"]
    gaps = (
        f"capture named nothing in {ev['capture_gap_hours']} h"
        if ev["capture_gap_hours"]
        else "capture: no hour without names"
    )
    out.append(
        f"  Evidence   {gaps}   conntrack lost events: {ev['lost_event_runs']} run(s)   {_cut_text(ev, long)}"
    )
    on = [x for x in sec["hours"] if x["class"] != "off"]
    c = sec["hour_counts"]

    def which(cls: str) -> str:
        hs = [x for x in on if x["class"] == cls]
        if not hs:
            return ""
        label = "; ".join(f"{x['reasons'][0]} {_hm(x['h'], long)[:-3]}h" for x in hs[:4])
        return f" ({label}{'; ...' if len(hs) > 4 else ''})"

    out.append(
        f"  Hours      TV on {len(on)}: clean {c['clean']}, confounded {c['confounded']}"
        f"{which('confounded')}, no demand {c['no_demand']}{which('no_demand')}"
    )
    if not sec["samples"]:
        out.append("  (no gateway samples in this window: is `tvgw verify --record` running with LEDGER=on?)")
    return out


def pack_entry(sec: dict | None) -> dict:
    """The analyst's counts-only copy (`changes_in_effect` in the pack): change kinds with their counts,
    the hour classes, and the confounder labels with how many hours each cost. Never a subject, a
    trigger, a detail or a time: a model that sees "firmware changed, PIA was down two hours" weighs
    new names and gaps accordingly, and needs nothing more to do it."""
    if not sec:
        return {}
    kinds: dict[str, int] = {}
    for g in sec["groups"].values():
        for e in g["events"]:
            kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        for cnt in g["counts"]:
            kinds[cnt["kind"]] = kinds.get(cnt["kind"], 0) + cnt["n"]
    confounders: dict[str, int] = {}
    for x in sec["hours"]:
        if x["class"] == "confounded":
            for r in dict.fromkeys("PIA not connected" if r.startswith("PIA ") else r for r in x["reasons"]):
                confounders[r] = confounders.get(r, 0) + 1  # a closed vocabulary: no state word passes
    return {
        "changes": dict(sorted(kinds.items())),
        "hours": dict(sec["hour_counts"]),
        "confounded_by": dict(sorted(confounders.items())),
        "firmware_changes": sec["tv"]["firmware_changes"],
        "machine_rules_on_trial": len(sec["on_trial"]),
    }
