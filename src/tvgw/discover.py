"""Find the TV on the gateway's TV-side network and learn its identity, so the operator never has to
look up a MAC address.

Evidence, in order of reliability on a TV that has its sharing features switched off (most do once
the owner has been through the privacy menus): the DHCP lease dnsmasq gave it (address, MAC, the
hostname the TV announced: webOS says `LGwebOSTV`), the kernel's neighbour table, the vendor LAN-API
ports the TV listens on (webOS: 3000/3001; Tizen: 8001/8002; Roku: 8060; Cast/Android TV: 8008/8009;
SmartCast: 7345/9000), and, when the TV still answers it, an SSDP search whose UPnP description
carries the manufacturer and model. Everything that touches the network is injectable.

(profile) The evidence names a vendor easily and a profile rarely: `assign()` gives a device a bundled
profile only on two signals that agree, every port of a row open and a host-name hint of the same vendor,
or on one that only that vendor's TV gives, an answer to its own SSDP search target (LG's second-screen
service). One signal alone names a vendor, never a profile, and setup asks the TV's owner about it
(design decision 62). The rows below are v0.2.0's; only LG's name a profile.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import tempfile
import time
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from tvgw import profile as profile_mod
from tvgw.profile import Profile

LEASES = "/var/lib/misc/dnsmasq.leases"
SSDP_GROUP = ("239.255.255.250", 1900)
SSDP_TARGETS = (
    "urn:lge-com:service:webos-second-screen:1",
    "urn:dial-multiscreen-org:service:dial:1",
    "upnp:rootdevice",
    "ssdp:all",
)
# (ports that must all be open) -> (vendor, platform, profile or None)
PORT_SIGNATURES = (
    ((3000, 3001), ("LG", "webOS", "lg-webos")),
    ((8001, 8002), ("Samsung", "Tizen", None)),
    ((8060,), ("Roku", "Roku OS", None)),
    ((7345, 9000), ("Vizio", "SmartCast", None)),
    ((8008, 8009), ("Google", "Android TV / Cast", None)),
)
HOSTNAME_HINTS = (
    ("lgwebostv", ("LG", "webOS", "lg-webos")),
    ("samsung", ("Samsung", "Tizen", None)),
    ("roku", ("Roku", "Roku OS", None)),
    ("vizio", ("Vizio", "SmartCast", None)),
    ("bravia", ("Sony", "Android TV", None)),
    ("firetv", ("Amazon", "Fire TV", None)),
    ("amazon-", ("Amazon", "Fire TV", None)),
    ("chromecast", ("Google", "Cast", None)),
    ("googletv", ("Google", "Android TV", None)),
)
# (profile) a search target only one vendor's TV answers -> (vendor, platform, profile): one signal that
# is enough, unlike a port or a host name, which another device can have or claim as well
SSDP_SIGNATURES = (("urn:lge-com:service:webos-second-screen:1", ("LG", "webOS", "lg-webos")),)
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


@dataclass
class Candidate:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    platform: str = ""
    model: str = ""
    profile: str | None = None  # (profile) assigned on evidence only, by assign()
    evidence: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)  # (profile) LAN-API ports that accepted a connection
    ssdp_targets: list[str] = field(default_factory=list)  # (profile) the search targets it answered

    @property
    def label(self) -> str:
        who = " ".join(x for x in (self.vendor, self.platform, self.model) if x) or "unknown device"
        return f"{self.ip}  {self.mac or '(no MAC)'}  {self.hostname or '-'}  {who}"


# ---- sources --------------------------------------------------------------------------
def parse_leases(text: str) -> list[tuple[str, str, str]]:
    """dnsmasq leases: `expiry mac ip hostname client-id` -> (mac, ip, hostname); `*` means no name."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and MAC_RE.match(parts[1].lower()):
            out.append((parts[1].lower(), parts[2], "" if parts[3] == "*" else parts[3]))
    return out


def parse_neigh(json_text: str) -> list[tuple[str, str, str]]:
    """`ip -j neigh show dev IFACE` -> (ip, mac, state) for entries with a MAC."""
    try:
        rows = json.loads(json_text) if json_text.strip() else []
    except ValueError:
        return []
    out = []
    for r in rows:
        if isinstance(r, dict) and r.get("lladdr") and r.get("dst"):
            state = r.get("state") or []
            out.append(
                (
                    r["dst"],
                    str(r["lladdr"]).lower(),
                    ",".join(state) if isinstance(state, list) else str(state),
                )
            )
    return out


def dhcp_names(journal_text: str) -> dict[str, str]:
    """dnsmasq's DHCP log lines `... client provides name: X` keyed by the MAC of the same transaction
    (`DHCPREQUEST(eth0) ip mac`), for TVs whose lease has no name yet."""
    names: dict[str, str] = {}
    last_mac = ""
    for line in journal_text.splitlines():
        m = re.search(r"DHCP(?:REQUEST|DISCOVER|ACK)\(\S+\) \S+ ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})", line)
        if m:
            last_mac = m.group(1).lower()
        m = re.search(r"client provides name: (\S+)", line)
        if m and last_mac:
            names[last_mac] = m.group(1)
    return names


def tcp_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def fingerprint(
    ip: str, probe: Callable[[str, int], bool] = tcp_open, opened: list[int] | None = None
) -> tuple[tuple[str, str, str | None] | None, list[str]]:
    """Vendor by the LAN-API ports a TV listens on. Returns (signature or None, evidence lines), and adds
    every port that accepted a connection to `opened` when it is given."""
    evidence = []
    for ports, sig in PORT_SIGNATURES:
        open_ports = [p for p in ports if probe(ip, p)]
        if opened is not None:
            opened += [p for p in open_ports if p not in opened]
        if len(open_ports) == len(ports):
            evidence.append(f"tcp {'/'.join(map(str, ports))} open ({sig[1]} LAN API)")
            return sig, evidence
        if open_ports:
            evidence.append(f"tcp {'/'.join(map(str, open_ports))} open")
    return None, evidence


def hostname_hint(name: str) -> tuple[str, str, str | None] | None:
    low = name.lower()
    return next((sig for needle, sig in HOSTNAME_HINTS if needle in low), None)


# ---- (profile) assignment on evidence (design decision 62) -------------------------------------------
@dataclass(frozen=True)
class Assignment:
    """The profile a device gets and why. `profile` is a bundled profile assigned on evidence, or None;
    `vendor` is the brand the signals point to, from one signal alone if need be, and is what setup asks
    the owner about; `evidence` says what decided."""

    profile: str | None
    vendor: str
    evidence: tuple[str, ...]


def _vendor_key(vendor: str) -> str:
    return re.sub(r"[^a-z0-9]", "", vendor.lower())


def bundled_profiles() -> tuple[Profile, ...]:
    """Every profile the package ships, loaded: what assign() may choose from."""
    return tuple(profile_mod.load(name) for name in profile_mod.bundled_names())


def vendor_profile(vendor: str, profiles: Iterable[Profile]) -> str | None:
    """The bundled profile for a brand (`[profile] vendor`, compared without case or punctuation, so
    `VIZIO` and `Vizio` agree), or None: the general profile has no vendor and is never one."""
    key = _vendor_key(vendor)
    return next((p.name for p in profiles if key and _vendor_key(p.vendor) == key), None)


def assign(candidate: Candidate, profiles: Iterable[Profile]) -> Assignment:
    """The profile `candidate` gets on its evidence, among `profiles` (design decision 62).

    A profile is assigned when the device answered a search target only its vendor's TV answers
    (SSDP_SIGNATURES), or when every port of a PORT_SIGNATURES row accepted a connection and a
    HOSTNAME_HINTS entry names the same profile. Anything less (the ports alone, a host name alone,
    a UPnP manufacturer, rows that disagree) names at most a vendor. A profile not in `profiles` is
    never assigned."""
    names = {p.name for p in profiles}
    ssdp = next((sig for target, sig in SSDP_SIGNATURES if target in candidate.ssdp_targets), None)
    if ssdp and ssdp[2] in names:
        return Assignment(ssdp[2], ssdp[0], (f"answered {ssdp[0]}'s own SSDP search target",))
    opened = set(candidate.open_ports)
    row = next(((ports, sig) for ports, sig in PORT_SIGNATURES if set(ports) <= opened), None)
    hint = hostname_hint(candidate.hostname) if candidate.hostname else None
    if row and hint and row[1][2] and row[1][2] == hint[2] and row[1][2] in names:
        ports = "/".join(map(str, row[0]))
        why = f"tcp {ports} open and the host name {candidate.hostname!r} agree"
        return Assignment(row[1][2], row[1][0], (why,))
    vendor = candidate.vendor or (row[1][0] if row else "") or (hint[0] if hint else "")
    seen = [
        *([f"tcp {'/'.join(map(str, row[0]))} open"] if row else []),
        *([f"the host name {candidate.hostname!r}"] if hint else []),
    ]
    if not vendor:
        why = "no signal names a vendor"
    elif row and hint and row[1][0] != hint[0]:
        why = f"{' and '.join(seen)} name different vendors: no profile"
    elif row and hint:  # the two agree, on a vendor whose rows name no profile that is offered
        why = f"{' and '.join(seen)} name {vendor}, and no discovery row gives it a profile offered here"
    else:
        source = seen[0] if seen else "its UPnP description"
        why = f"one signal names {vendor} ({source}): no profile on that alone"
    return Assignment(None, vendor, (why,))


def vendor_phrase(vendor: str) -> str:
    """'an LG', 'a Samsung': the article as the name is said. A short name in capitals is said letter
    by letter, so it takes 'an' before a letter whose name starts with a vowel sound."""
    if vendor.isupper() and len(vendor) <= 4:
        spoken = vendor[:1] in "AEFHILMNORSX"
    else:
        spoken = vendor[:1].lower() in "aeiou"
    return ("an " if spoken else "a ") + vendor


# ---- SSDP (optional: many TVs stop answering once sharing is switched off) -----------------------
def parse_ssdp(payload: bytes) -> dict[str, str]:
    head = payload.decode("utf-8", "replace").split("\r\n")
    out = {}
    for line in head[1:]:
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip().lower()] = v.strip()
    return out


def parse_description(xml: str) -> dict[str, str]:
    out = {}
    for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription", "UDN"):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.S)
        if m:
            out[tag] = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
    return out


def ssdp_search(
    bind_ip: str, timeout: float = 4.0, on_bound: Callable[[int], None] | None = None
) -> dict[str, dict[str, str]]:
    """M-SEARCH on the TV-side interface; responders by address with their headers. `on_bound` is
    told the socket's port before anything is sent: the answers come back by unicast to it. (profile)
    A responder's headers are its first answer's, except `st`, which lists every search target it
    answered, space-separated, since one of them may be the vendor's own (SSDP_SIGNATURES)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.bind(("", 0))
        if on_bound:
            on_bound(s.getsockname()[1])
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
        s.settimeout(0.5)
        for st in SSDP_TARGETS:
            msg = (
                f'M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_GROUP[0]}:{SSDP_GROUP[1]}\r\nMAN: "ssdp:discover"\r\n'
                f"MX: 3\r\nST: {st}\r\nUSER-AGENT: tvgw UPnP/1.1\r\n\r\n"
            ).encode()
            try:
                s.sendto(msg, SSDP_GROUP)
            except OSError:
                return {}
        seen: dict[str, dict[str, str]] = {}
        targets: dict[str, list[str]] = {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = s.recvfrom(8192)
            except TimeoutError:
                continue
            except OSError:
                break
            hdr = parse_ssdp(data)
            if "location" in hdr:
                seen.setdefault(addr[0], hdr)
                answered = targets.setdefault(addr[0], [])
                if hdr.get("st") and hdr["st"] not in answered:
                    answered.append(hdr["st"])
        for ip, hdr in seen.items():
            hdr["st"] = " ".join(targets[ip])
        return seen
    finally:
        s.close()


def location_ok(url: str, responder_ip: str) -> bool:
    """An SSDP LOCATION we are willing to fetch as root: plain http, to the very address that answered
    the search (an IP literal, never a name that could resolve to loopback or the gateway), with no
    credentials and a sane port. Anything else is a device trying to steer the installer."""
    try:
        u = urlsplit(url)
        if u.scheme != "http" or u.username is not None or u.password is not None:
            return False
        port = u.port  # ValueError for a non-numeric or out-of-range port
        return ipaddress.ip_address(u.hostname or "") == ipaddress.ip_address(responder_ip) and (
            port is None or 1 <= port <= 65535
        )
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A 3xx is an error, not a hop: the pinned address must serve the description itself."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_only_opener() -> urllib.request.OpenerDirector:
    # built by hand: build_opener() would add file://, ftp://, data: and proxy handlers
    o = urllib.request.OpenerDirector()
    for h in (
        urllib.request.HTTPHandler(),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.UnknownHandler(),  # any other scheme raises URLError instead of returning None
        _NoRedirect(),
    ):
        o.add_handler(h)
    return o


_OPENER = _http_only_opener()


def fetch_description(url: str, timeout: float = 3.0, responder_ip: str | None = None) -> dict[str, str]:
    """The UPnP description behind an SSDP LOCATION, read on a first install as root: pinned to the
    responder when its address is given (location_ok), http only, no redirects, at most 64 KiB."""
    if responder_ip is not None and not location_ok(url, responder_ip):
        return {}
    if not url.startswith("http://"):
        return {}
    try:
        with _OPENER.open(url, timeout=timeout) as fh:
            return parse_description(fh.read(65536).decode("utf-8", "replace"))
    except (OSError, ValueError):
        return {}


# ---- putting it together ------------------------------------------------------------------
def run_cmd(cmd: list[str]) -> str:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def discover(
    iface: str,
    gw_ip: str,
    leases_text: str = "",
    neigh_json: str = "",
    journal_text: str = "",
    probe: Callable[[str, int], bool] = tcp_open,
    ssdp: Callable[[str], dict[str, dict[str, str]]] | None = None,
    describe: Callable[[str], dict[str, str]] = fetch_description,
    profiles: Iterable[Profile] | None = None,
) -> list[Candidate]:
    """Merge every source into one candidate per address on the TV side, the gateway excluded, each
    with the profile assign() gives it among `profiles` (the bundled ones by default)."""
    by_ip: dict[str, Candidate] = {}
    profiles = bundled_profiles() if profiles is None else tuple(profiles)

    def cand(ip: str) -> Candidate:
        return by_ip.setdefault(ip, Candidate(ip=ip))

    names = dhcp_names(journal_text)
    for mac, ip, name in parse_leases(leases_text):
        c = cand(ip)
        c.mac, c.hostname = mac, name or names.get(mac, "")
        c.evidence.append("DHCP lease" + (f" (announced as {c.hostname})" if c.hostname else ""))
    for ip, mac, state in parse_neigh(neigh_json):
        c = cand(ip)
        c.mac = c.mac or mac
        c.evidence.append(f"neighbour table ({state or 'seen'})")
    for ip, hdr in (ssdp(gw_ip) if ssdp else {}).items():
        c = cand(ip)
        loc = hdr.get("location", "")
        # the description is fetched only from the address that answered (see location_ok)
        desc = describe(loc) if loc and location_ok(loc, ip) else {}
        c.model = desc.get("modelName") or desc.get("modelNumber") or c.model
        if desc.get("manufacturer"):
            c.vendor = c.vendor or desc["manufacturer"].split()[0]
        c.evidence.append("SSDP: " + (desc.get("friendlyName") or hdr.get("server", "answered")))
        c.ssdp_targets = hdr.get("st", "").split()
        if loc and not location_ok(loc, ip):
            c.evidence.append("SSDP LOCATION points off-device; not fetched")
    by_ip.pop(gw_ip, None)
    for c in by_ip.values():
        sig, ev = fingerprint(c.ip, probe, c.open_ports)
        c.evidence += ev
        hint = hostname_hint(c.hostname) if c.hostname else None
        for s in (sig, hint):
            if s:
                c.vendor, c.platform = c.vendor or s[0], c.platform or s[1]
        c.profile = assign(c, profiles).profile  # (profile) on evidence only
    return sorted(by_ip.values(), key=lambda c: (c.profile is None, c.ip))


# (guard) the guard runs after inet tvgw and drops what inet tvgw accepted unless the same hole is in
# it too (design decision 42)
GUARD_TABLE = ("inet", "tvgw_guard")


def _ssdp_with_exemption(iface: str):
    """The gateway's own output chain drops the Pi's multicast chatter into the TV subnet (by design),
    which also stops an SSDP search, and its input chains drop what the TV sends to any other port of
    the Pi, which stops the answers: they come back by unicast from the TV to the search socket, a flow
    conntrack cannot tie to a search sent to the multicast group. Open exactly those holes for the
    duration of the search, in each table that is loaded, and close them all again whatever happens.
    The input hole goes at the head of inet tvgw's input chain and of the guard's: the guard runs
    after inet tvgw, and without inet tvgw (a first install) it is the only input chain there is."""

    def search(bind_ip: str) -> dict[str, dict[str, str]]:
        rule = [
            "inet",
            "tvgw",
            "output",
            "oifname",
            iface,
            "udp",
            "dport",
            "1900",
            "counter",
            "accept",
            "comment",
            "tvgw-discover",
        ]
        opened = run_cmd(["nft", "insert", "rule", *rule]) is not None and "tvgw-discover" in run_cmd(
            ["nft", "-a", "list", "chain", "inet", "tvgw", "output"]
        )
        inputs = [("inet", "tvgw")] if opened else []
        if run_cmd(["nft", "list", "chain", *GUARD_TABLE, "input"]).strip():
            inputs.append(GUARD_TABLE)

        def open_input(port: int) -> None:  # the answers: from the TV side to the socket's port
            for family, table in inputs:
                run_cmd(
                    [
                        "nft",
                        "insert",
                        "rule",
                        family,
                        table,
                        "input",
                        "iifname",
                        iface,
                        "ip",
                        "daddr",
                        bind_ip,
                        "udp",
                        "dport",
                        str(port),
                        "counter",
                        "accept",
                        "comment",
                        "tvgw-discover",
                    ]
                )

        try:
            return ssdp_search(bind_ip, on_bound=open_input if inputs else None)
        finally:
            holes = ([("inet", "tvgw", "output")] if opened else []) + [(f, t, "input") for f, t in inputs]
            for family, table, chain in holes:
                for line in run_cmd(["nft", "-a", "list", "chain", family, table, chain]).splitlines():
                    if "tvgw-discover" in line and "# handle" in line:
                        run_cmd(
                            [
                                "nft",
                                "delete",
                                "rule",
                                family,
                                table,
                                chain,
                                "handle",
                                line.rsplit("handle", 1)[1].strip(),
                            ]
                        )

    return search


def gather(iface: str, gw_ip: str, leases_path: str = LEASES, with_ssdp: bool = True) -> list[Candidate]:
    """discover() on the live system."""
    try:
        with open(leases_path, encoding="utf-8", errors="replace") as fh:
            leases = fh.read()
    except OSError:
        leases = ""
    return discover(
        iface,
        gw_ip,
        leases_text=leases,
        neigh_json=run_cmd(["ip", "-j", "neigh", "show", "dev", iface]),
        journal_text=run_cmd(["journalctl", "-u", "dnsmasq", "--no-pager", "-o", "cat", "-n", "2000"]),
        ssdp=_ssdp_with_exemption(iface) if with_ssdp else None,
    )


def safe_name(hostname: str, fallback: str = "tv") -> str:
    name = re.sub(r"[^A-Za-z0-9_-]+", "", hostname).lower()
    return name[:32] or fallback


def write_identity(conf_text: str, mac: str, ip: str, name: str, profile: str | None) -> str:
    """tvgw.conf with TV_MAC/TV_IP/TV_NAME (and PROFILE when known) set, comments and order kept."""
    values = {"TV_MAC": mac, "TV_IP": ip, "TV_NAME": name}
    if profile:
        values["PROFILE"] = profile
    lines = conf_text.splitlines()
    seen = set()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*([A-Z][A-Z0-9_]*)=", line)
        if m and m.group(1) in values:
            key = m.group(1)
            comment = line.partition("#")[2]
            lines[i] = f"{key}={values[key]}" + (f"   #{comment}" if comment else "")
            seen.add(key)
    for key, value in values.items():
        if key not in seen:
            lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


def write_conf(path: str | os.PathLike, text: str) -> None:
    """Replace the settings file whole: a new file beside it, fsynced, with the old one's mode and owner
    (640 root:adm on the gateway; 640 for a new one), renamed over it, then the directory fsynced.
    Written in place, a power cut mid-write left a truncated conf, and tvgw-apply stops at boot on a
    missing WAN_GW, leaving the TV dark."""
    path = os.path.abspath(path)
    fd, tmp = tempfile.mkstemp(prefix=".tvgw.conf.", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            st = os.stat(path)
        except FileNotFoundError:
            os.chmod(tmp, 0o640)
        else:
            os.chown(tmp, st.st_uid, st.st_gid)
            os.chmod(tmp, stat.S_IMODE(st.st_mode))
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    dfd = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def render(cands: Iterable[Candidate]) -> list[str]:
    out = []
    for i, c in enumerate(cands, 1):
        out.append(f"{i}. {c.label}")
        for e in c.evidence:
            out.append(f"      {e}")
        if c.profile:
            out.append(f"      profile: {c.profile}")
    return out
