"""`tvgw web`: the brief on your phone, a read-only page on the home network behind a password (design
decision 76).

`tvgw web serve` is `tvgw-web.service`'s process, run as the system user `tvgw-web` (in `adm`, so it reads
the settings and the store as `tvgw brief` does). It serves HTTPS with the owner's own certificate on the
uplink's IPv4 address (`WAN_IF`, read at start) or, with `WEB_BIND=loopback`, on 127.0.0.1, and refuses to
start bound to `GW_IP`, an address in `TV_NET`, a wildcard, or any address outside the home's private
ranges. Its unit adds a cgroup filter that admits only those ranges and loopback (`dropin`), and the guard
drops anything from the TV to any address of the gateway but `GW_IP`'s DHCP, DNS, 80 and 443.

Read-only by construction: the store is opened `mode=ro` with `query_only`; no page writes a file, runs a
command or takes SQL; every value from the record is escaped (`webpages.esc`). Nothing from the record
reaches the journal: the server logs its start, its stop and each sign-in's outcome, with the time journald
gives the line and nothing else.

`sudo tvgw web cert` makes the certificate (`openssl`, P-256, about two years), `sudo tvgw web password`
stores the password's scrypt hash, `sudo tvgw web status` says how the page stands, and `tvgw web dropin`
prints the unit's address filter for install.sh.
"""

from __future__ import annotations

import contextlib
import grp
import hashlib
import heapq
import hmac
import http.client
import io
import ipaddress
import math
import os
import re
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import OrderedDict
from collections.abc import Callable
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tvgw import config, db, webauth, webpages
from tvgw.config import Settings
from tvgw.profile import Profile

UNIT = "tvgw-web"
USER = GROUP = "tvgw-web"
MAX_CONNECTIONS = 32  # connections at once; one more is closed unread
MAX_REQUESTS = 16  # requests handled at once; one more gets 503
SOCKET_TIMEOUT = 10  # seconds a connection may stay silent, the TLS handshake included
MAX_BODY = 4096  # bytes of a POST body
MAX_PATH = 600  # characters of a request's target
MAX_HEAD = 16 * 1024  # bytes of a request's line and headers together: 431 beyond
MAX_PER_ADDRESS = 4  # connections at once from one address; one more is closed unread
REQUEST_DEADLINE = 15  # seconds from accept to a whole request (TLS handshake, line, headers, body)
RESPONSE_DEADLINE = 90  # seconds from then to make and send the page (a brief may wait BUILD_WAIT to build)
BUILD_WAIT = 30  # seconds a page waits while another builds a brief, before it says busy
# a finished day is kept once its evidence has landed: three hours after it ends, as tvgw-analyze's SETTLE
SETTLE = 10800
CACHE_DAYS = 14  # finished days' briefs kept in memory
SUMMARY_DAYS = 64  # finished days' rows of the 14-day table kept in memory
TABLE_DAYS = 14
NAME_DAYS = 14  # days of lookups a name's page shows
NEW_SHOWN = 50  # names first seen in a day the day's page lists
UNDER_SHOWN = 50  # names under a domain its page lists
CERT_DAYS = 730  # about two years
CERT_WARN_DAYS = 30  # tvgw verify warns this long before the certificate ends
SESSION_COOKIE = "__Host-tvgw-session"
FORM_COOKIE = "__Host-tvgw-form"
FORM_MAX_AGE = 3600  # seconds the sign-in form's cookie lasts
DEVICE_COOKIE = "__Host-tvgw-device"  # a known device: spared the limit for unknown devices, signs nobody in
DEVICE_MAX_AGE = 400 * 86400  # seconds: the longest a browser keeps a cookie
CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none';"
    " base-uri 'none'"
)
HEADERS = (
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
)
LOOPBACK = "127.0.0.1"
PAGES = frozenset({"/", "/rules", "/about", "/name"})  # with /day/<day>, /day/<day>/full and /name/<name>
_HOSTNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
SIOCGIFADDR = 0x8915  # Linux's ioctl for an interface's IPv4 address


class WebError(Exception):
    """Something the owner must fix before the page can start, said in plain words."""


def log(message: str) -> None:
    """One line to the journal: never a name, an address or anything from the record."""
    print(f"tvgw web: {message}", flush=True)


# ---- where it listens ----------------------------------------------------------------------------------
def ipv4_of(ifname: str) -> str | None:
    """The interface's IPv4 address, by the SIOCGIFADDR ioctl: no subprocess and no netlink socket, so the
    unit's sandbox (AF_INET and AF_UNIX only) allows it. None when it has none or the call fails."""
    import fcntl
    import struct

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            got = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack("256s", ifname.encode()[:15]))
        except OSError:
            return None
    return socket.inet_ntoa(got[20:24])


def bind_address(s: Settings, find: Callable[[str], str | None] = ipv4_of) -> str:
    """127.0.0.1 with WEB_BIND=loopback; else WAN_IF's IPv4 address now, or WebError when it has none."""
    if s.web_bind == "loopback":
        return LOOPBACK
    found = find(s.wan_if)
    if not found:
        raise WebError(f"{s.wan_if} has no IPv4 address yet")
    return found


def check_bind(address: str, s: Settings) -> None:
    """WebError unless `address` is one the page may listen on: loopback, or a single IPv4 address inside
    the home's private ranges (10/8, 172.16/12, 192.168/16) that is not GW_IP and not in TV_NET. A
    wildcard, the TV side and anything reachable from outside the home are refused."""
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        raise WebError(f"{address!r} is not an IPv4 address") from None
    if ip.is_unspecified:
        raise WebError("the page never listens on every address at once")
    if str(ip) == s.gw_ip or ip in ipaddress.IPv4Network(s.tv_net):
        raise WebError("the page never listens on the TV's side of the gateway")
    if s.web_bind == "loopback":
        if str(ip) != LOOPBACK:
            raise WebError("WEB_BIND=loopback listens on 127.0.0.1 only")
        return
    if ip.is_loopback or not any(ip in net for net in config.PRIVATE_NETS):
        raise WebError("the uplink's address is not a home network's private address, so the page stays off")


LISTEN = "0A"  # a socket's state in /proc/net/tcp: TCP_LISTEN


def tcp_listeners(tcp: str | None, tcp6: str | None, port: int) -> list[str]:
    """The local addresses with a TCP socket listening on `port`, from /proc/net/tcp and /proc/net/tcp6
    (addresses in the host's byte order, a word at a time), each once, IPv4 first. `tvgw verify` and
    `tvgw web status` read them."""
    import struct

    found: list[str] = []
    for text, width in ((tcp, 8), (tcp6, 32)):
        for line in (text or "").splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != LISTEN or ":" not in fields[1]:
                continue
            hexaddr, _, hexport = fields[1].partition(":")
            try:
                if int(hexport, 16) != port or len(hexaddr) != width:
                    continue
                words = [int(hexaddr[i : i + 8], 16) for i in range(0, width, 8)]
                raw = struct.pack(f"={len(words)}I", *words)
            except (ValueError, struct.error):
                continue
            address = str(ipaddress.ip_address(raw))
            if address not in found:
                found.append(address)
    return found


def allowed_sources(tv_net: str) -> list[str]:
    """What the unit's cgroup filter admits: loopback and the home's private ranges, less TV_NET."""
    net = ipaddress.IPv4Network(tv_net)
    out = ["127.0.0.0/8"]
    for private in config.PRIVATE_NETS:
        if net.subnet_of(private):
            out += [str(p) for p in sorted(private.address_exclude(net))]
        else:
            out.append(str(private))
    return out


def dropin(s: Settings) -> str:
    """tvgw-web.service.d/not-from-tv.conf, from the settings: every address denied, then loopback and the
    private ranges but TV_NET allowed (systemd lets an allowed address through whatever the deny list says,
    so TV_NET is cut out of the ranges rather than denied beside them); no interface but loopback and
    WAN_IF (loopback alone with WEB_BIND=loopback), so never TV_IF; and no port but WEB_PORT to bind (the
    unit denies every other)."""
    interfaces = "lo" if s.web_bind == "loopback" else f"lo {s.wan_if}"
    return (
        "# tvgw (design decision 76): the page answers this computer and the home network's private\n"
        "# addresses, never the TV subnet and never an address outside the home, on loopback and the\n"
        "# uplink alone, and binds its own port alone. Written by deploy/install.sh from TV_NET, WAN_IF,\n"
        "# WEB_BIND and WEB_PORT in /etc/tvgw/tvgw.conf; edits here are replaced at the next install.\n"
        "[Service]\n"
        "IPAddressDeny=any\n"
        f"IPAddressAllow={' '.join(allowed_sources(s.tv_net))}\n"
        f"RestrictNetworkInterfaces={interfaces}\n"
        f"SocketBindAllow=ipv4:tcp:{s.web_port}\n"
    )


def allowed_hosts(address: str, hostname: str, loopback: bool) -> frozenset[str]:
    """The names a request's Host may give: the address it listens on, the gateway's host name with and
    without `.local`, and on loopback `localhost`. Anything else (another site's name pointed at this
    address) is refused with 421."""
    names = {address}
    if _HOSTNAME.fullmatch(hostname or ""):
        names |= {hostname.lower(), f"{hostname.lower()}.local"}
    if loopback:
        names |= {"localhost", LOOPBACK}
    return frozenset(names)


# ---- the certificate -----------------------------------------------------------------------------------
def fingerprint(pem: str) -> str | None:
    """The SHA-256 fingerprint of the first certificate in `pem`, as browsers show it (`AB:CD:...`)."""
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (ValueError, TypeError):
        return None
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def cert_names(hostname: str, address: str | None) -> tuple[list[str], list[str]]:
    """(DNS names, IP addresses) the certificate names: the host name with `.local` first, the bare host
    name, `localhost` and 127.0.0.1 for a tunnel, and the uplink's address when it has one."""
    names = []
    if _HOSTNAME.fullmatch(hostname or ""):
        names += [f"{hostname.lower()}.local", hostname.lower()]
    names.append("localhost")
    ips = ([address] if address and address != LOOPBACK else []) + [LOOPBACK]
    return names, ips


def openssl_command(
    key: str, cert: str, names: list[str], ips: list[str], days: int = CERT_DAYS
) -> list[str]:
    """`openssl req` making a self-signed P-256 certificate for a server: no CA, digital signature only,
    server authentication only, and every name in subjectAltName (what browsers check)."""
    san = ",".join([f"DNS:{n}" for n in names] + [f"IP:{ip}" for ip in ips])
    return [
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-sha256", "-days", str(days), "-subj", f"/CN={names[0]}", "-keyout", key, "-out", cert,
        "-addext", f"subjectAltName={san}", "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth",
    ]  # fmt: skip


def cert_end(path: str, run: Callable[[list[str]], str]) -> float | None:
    """When the certificate at `path` ends, in epoch seconds, from `openssl x509 -enddate`; None when it
    cannot be read."""
    out = run(["openssl", "x509", "-noout", "-enddate", "-in", path])
    m = re.search(r"notAfter=(.+)", out)
    if not m:
        return None
    try:
        return float(ssl.cert_time_to_seconds(m.group(1).strip()))
    except ValueError:
        return None


def tls_context(cert: str, key: str) -> ssl.SSLContext:
    """TLS 1.2 or newer, forward-secret AEAD ciphers only for 1.2 (1.3's are fixed), no compression, no
    renegotiation, the server's order of preference."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(cert, key)
    return ctx


# ---- what the pages show -------------------------------------------------------------------------------
def open_store(path: str) -> sqlite3.Connection:
    """The store, read-only twice over: `mode=ro`, and `query_only`, so even a statement that would write
    is refused by SQLite itself."""
    conn = db.connect(path, readonly=True, timeout=5)
    conn.execute("PRAGMA query_only=1")
    return conn


def _brief_kw(s: Settings) -> dict:
    """What `tvgw report` passes, so the page shows what the daily report shows: never the minute-level
    sessions of the app in front (`app_in_front` stays False, design decision 67)."""
    return {
        "gw_ip": s.gw_ip,
        "ledger_on": s.ledger == "on",
        "clean_hours": s.judge2_clean_hours,
        "upload_ceiling": s.upload_ceiling,
    }


def day_end(day: str) -> float:
    from tvgw import queries

    return queries.day_bounds(day)[1]


class Cache:
    """At most `size` finished days, the newest use last. Emptied whenever the record starts again: `tvgw
    forget` empties `ingest_runs`, so the store's first ingest changes, and a forgotten day is never shown
    from memory."""

    def __init__(self, size: int):
        self.size = size
        self._items: OrderedDict[str, object] = OrderedDict()
        self._generation: object = None
        self._lock = threading.Lock()

    def get(self, generation: object, key: str):
        with self._lock:
            if generation != self._generation:
                self._items.clear()
                self._generation = generation
                return None
            if key in self._items:
                self._items.move_to_end(key)
                return self._items[key]
            return None

    def put(self, generation: object, key: str, value: object) -> None:
        with self._lock:
            if generation != self._generation:
                self._items.clear()
                self._generation = generation
            self._items[key] = value
            self._items.move_to_end(key)
            while len(self._items) > self.size:
                self._items.popitem(last=False)

    def __len__(self) -> int:
        return len(self._items)


class Record:
    """The pages' reads of the store, with the finished days kept (CACHE_DAYS briefs, SUMMARY_DAYS table
    rows), so the gateway builds a finished day's brief once. One brief is built at a time (BUILD_WAIT),
    so a phone can never take the gateway's processor from its own work."""

    def __init__(self, s: Settings, prof: Profile, clock: Callable[[], float] = time.time):
        self.s, self.prof, self.clock = s, prof, clock
        self.briefs = Cache(CACHE_DAYS)
        self.rows = Cache(SUMMARY_DAYS)
        self.build = threading.Lock()

    def settled(self, day: str, now: float) -> bool:
        return day_end(day) + SETTLE <= now

    def first(self, conn) -> float | None:
        from tvgw import queries

        return queries.first_ingest(conn)

    def brief(self, conn, day: str) -> tuple[list[str], str, list[dict]]:
        """(the plain brief's lines, the engineering brief's text, the day's new names) for one day."""
        from tvgw import cli, queries

        now = self.clock()
        generation = self.first(conn)
        if self.settled(day, now):
            hit = self.briefs.get(generation, day)
            if hit is not None:
                return hit
        if not self.build.acquire(timeout=BUILD_WAIT):
            raise Busy()
        try:
            o = queries.brief(conn, day, self.prof, now=now, **_brief_kw(self.s))
            lines = cli.plain_lines(conn, o, self.prof, now=now)
            buf = io.StringIO()
            cli.render_brief(o, out=buf)
            news = [
                {"name": h["name"], "category": h.get("category") or "", "blocked": h.get("blocked")}
                for h in o.get("new_hosts") or []
            ]
            out = (lines, buf.getvalue(), news)
        finally:
            self.build.release()
        if self.settled(day, now):
            self.briefs.put(generation, day, out)
        return out

    def row(self, conn, day: str) -> webpages.DayRow:
        """One row of the 14-day table: the TV's hours on, its lookups of known tracking services that were
        refused, and its new services, by the plain brief's own functions over the same reads."""
        from tvgw import cli, plain, queries
        from tvgw.names import registrable_domain

        now = self.clock()
        generation = self.first(conn)
        if self.settled(day, now):
            hit = self.rows.get(generation, day)
            if hit is not None:
                return hit
        a, b = queries.day_bounds(day)
        if not self.build.acquire(timeout=BUILD_WAIT):
            raise Busy()
        try:
            cats = queries.categories(conn, a, b, self.prof, self.s.gw_ip)
            mini = {
                "since": a,
                "until": b,
                "tvstate": [
                    {"time": datetime.fromtimestamp(t).strftime("%H:%M"), "power": p, "app": app}
                    for t, p, app in queries.tvstate(conn, a, b)
                ],
            }
            activity = cli._activity(conn, mini)
            news = {registrable_domain(r[0]) for r in queries.new_hosts(conn, a, b) if r[8]}
        finally:
            self.build.release()
        lookups = sum(c.get("lookups", 0) for c in cats)
        refused = sum(c.get("blocked", 0) for c in cats if plain.is_tracking(c["category"]))
        if activity is None:
            hours = "-"
        elif round(activity.hours) == 0:
            hours = "off"
        else:
            hours = f"about {round(activity.hours)}" + (" (estimated)" if activity.estimated else "")
        row = webpages.DayRow(
            day=day,
            hours=hours,
            refused=f"{refused:,}" if lookups else "-",
            new=f"{len(news):,}" if lookups else "-",
        )
        if self.settled(day, now):
            self.rows.put(generation, day, row)
        return row

    def name(self, conn, name: str) -> webpages.NameView:
        """What the store holds of one name, or of the names under a registrable domain."""
        from tvgw import companies, plain
        from tvgw.names import registrable_domain

        h = conn.execute(
            "SELECT first_seen, last_seen, category, last_blocked FROM hosts WHERE name=?", (name,)
        ).fetchone()
        if h is None:
            like = "%." + name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            under = [
                (n, plain.category_label(c or "", self.prof), None if b is None else bool(b))
                for n, c, b in conn.execute(
                    "SELECT name, category, last_blocked FROM hosts WHERE name LIKE ? ESCAPE '\\'"
                    " ORDER BY name",
                    (like,),
                )
                if registrable_domain(n) == name
            ][:UNDER_SHOWN]
            return webpages.NameView(name=name, seen=False, under=under)
        first, last, category, last_blocked = h
        since = self.clock() - NAME_DAYS * 86400
        newest = conn.execute(
            "SELECT blocked, rule, filter_id FROM dns WHERE qname=? ORDER BY t DESC LIMIT 1", (name,)
        ).fetchone()
        days = [
            (d, int(n), int(b or 0))
            for d, n, b in conn.execute(
                "SELECT date(t,'unixepoch','localtime'), COUNT(*), COALESCE(SUM(blocked),0) FROM dns"
                " WHERE qname=? AND t >= ? GROUP BY 1 ORDER BY 1",
                (name, since),
            )
        ]
        blocked = bool(newest[0]) if newest else (None if last_blocked is None else bool(last_blocked))

        def when(t) -> str:
            return datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M") if t else "-"

        return webpages.NameView(
            name=name,
            seen=True,
            kind=plain.category_label(category or "", self.prof),
            company=companies.company(name),
            first=when(first),
            last=when(last),
            blocked=blocked,
            decided=decided_by(newest, self.groups()),
            days=days,
        )

    def groups(self) -> dict[str, list[str]] | None:
        """The filter's own rules by where each comes from (`adguardcfg.rule_groups`), or None when a rules
        file cannot be read."""
        from tvgw import adguardcfg

        try:
            return adguardcfg.rule_groups(self.prof, self.s)
        except (OSError, ValueError):
            return None


def decided_by(newest: tuple | None, groups: dict[str, list[str]] | None) -> str:
    """Which kind of rule decided the newest lookup of a name, in plain words, from the store's own record
    of the answer (its rule and list) and the rules tvgw wrote."""
    if newest is None:
        return "No lookup of it is kept."
    blocked, rule, filter_id = newest
    verb = "Blocked" if blocked else "Allowed"
    if not rule and not filter_id:
        return "Blocked by a rule the filter did not name." if blocked else "Allowed: no rule matched it."
    if isinstance(filter_id, int) and filter_id > 0:
        return f"{verb} by a shared list the gateway subscribes to."
    if isinstance(filter_id, int) and filter_id < 0:
        return f"{verb} by one of the filter's own features."
    where = {
        "profile": "the TV's profile",
        "local": "your own rules",
        "machine": "a rule the gateway added on its own",
    }
    for group, words in where.items():
        if groups and rule in groups.get(group, ()):
            return f"{verb} by {words}."
    if groups is None:
        return f"{verb} by one of the gateway's rules."
    return f"{verb} by a rule in none of the gateway's files."


def rules_view(s: Settings, prof: Profile) -> tuple[str | None, list[tuple[str, str, str, str]]]:
    """`tvgw rules --local` as (a sentence, rows of kind, name, when and why it was written, and why a line
    is not applied)."""
    from tvgw import localrules

    try:
        text = localrules.read_text(s.local_rules)
    except PermissionError:
        return "The gateway could not read your rules file.", []
    if text is None:
        return "You have written no rules of your own yet.", []
    found = localrules.entries_of(text)
    if not found:
        return "You have written no rules of your own yet.", []
    refused = dict(localrules.problems([e.line for e in found], prof))
    rows = []
    for e in found:
        kind = e.rule.kind if e.rule else "?"
        host = e.rule.host if e.rule else e.line
        why = e.note.lstrip("!# ").strip()
        rows.append((kind, host, why, f"not applied: {refused[e.line]}" if e.line in refused else ""))
    return None, rows


class Busy(Exception):
    """Another page is building a brief, and this one waited BUILD_WAIT."""


# ---- the server ----------------------------------------------------------------------------------------
class App:
    """What every request shares: the settings, the record, the sessions, the limits and the address."""

    def __init__(
        self,
        s: Settings,
        prof: Profile,
        address: str,
        *,
        hostname: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        status_path: str | None = None,
        hash_reader: Callable[[str], str | None] = webauth.read_hash,
    ):
        self.s, self.prof, self.address = s, prof, address
        self.clock, self.wall = clock, wall
        self.status_path = status_path
        self.read_hash = hash_reader
        self.record = Record(s, prof, wall)
        self.sessions = webauth.Sessions()
        self.limiter = webauth.Limiter()
        self.forms = webauth.FormTokens()
        self.devices = webauth.Devices()
        self.checking = threading.Lock()  # one password check at a time: each takes 32 MiB
        self.requests = threading.BoundedSemaphore(MAX_REQUESTS)
        self.hosts = allowed_hosts(
            address, socket.gethostname() if hostname is None else hostname, s.web_bind == "loopback"
        )

    def password(self) -> str | None:
        return self.read_hash(self.s.web_password)


def _cookies(header: str | None) -> dict[str, str]:
    """The page's own three cookies from a Cookie header; anything else, or a malformed value, is dropped."""
    out: dict[str, str] = {}
    for part in (header or "").split(";")[:64]:
        key, sep, value = part.strip().partition("=")
        if not sep:
            continue
        shape = webauth.DEVICE if key == DEVICE_COOKIE else webauth.TOKEN
        if key in (SESSION_COOKIE, FORM_COOKIE, DEVICE_COOKIE) and shape.fullmatch(value):
            out[key] = value
    return out


def _wait_words(seconds: float) -> str:
    """A wait in plain words, rounded up: "5 seconds", "2 minutes", "1 hour"."""
    s = max(1, math.ceil(seconds))
    if s < 90:
        return f"{s} second{'s' if s != 1 else ''}"
    m = math.ceil(s / 60)
    if m < 90:
        return f"{m} minutes"
    h = math.ceil(s / 3600)
    return f"{h} hour{'s' if h != 1 else ''}"


class Handler(BaseHTTPRequestHandler):
    server_version = "tvgw"  # no Python version in the Server header
    sys_version = ""
    protocol_version = "HTTP/1.0"  # one request per connection: nothing holds a thread between requests
    timeout = SOCKET_TIMEOUT
    server: Server

    # -- the base class's hooks: nothing to the journal, our headers on every response ------------------
    def version_string(self) -> str:
        return self.server_version

    def log_message(self, format, *args) -> None:
        return  # a request's path and the client's address never reach the journal

    def end_headers(self) -> None:
        for key, value in HEADERS:
            self.send_header(key, value)
        super().end_headers()

    def setup(self) -> None:
        super().setup()
        self.rfile = _HeadLimit(self.rfile, MAX_HEAD)
        self.watch: Watch | None = getattr(self.server.local, "watch", None)

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except http.client.LineTooLong:  # the request line alone ran over MAX_HEAD, before any header
            self.command, self.requestline, self.request_version = None, "", "HTTP/1.0"
            self.send_error(431)

    def parse_request(self) -> bool:
        ok = super().parse_request()
        if ok and self.request_version == "HTTP/0.9":  # a response without headers would lack ours
            self.send_error(400)
            return False
        return ok

    def send_error(self, code, message=None, explain=None) -> None:
        """Every error the base class makes (a malformed request line, headers too long, a method with no
        handler) as our own page, with our headers."""
        if self.request_version == "HTTP/0.9":
            self.request_version = "HTTP/1.0"
        code = int(code)
        if code == 501:
            code = 405
        self.close_connection = True
        extra = [("Allow", "GET, HEAD, POST")] if code == 405 else []
        self.respond(code, webpages.error(code), extra)

    # -- responding ------------------------------------------------------------------------------------
    def respond(
        self,
        code: int,
        body: str | bytes,
        extra: list[tuple[str, str]] | None = None,
        ctype: str = "text/html",
    ) -> None:
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in extra or []:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and code >= 200 and code not in (204, 304):
            with contextlib.suppress(OSError):
                self.wfile.write(data)

    def redirect(self, where: str, extra: list[tuple[str, str]] | None = None) -> None:
        self.respond(303, "", [("Location", where), *(extra or [])])

    # -- the methods -----------------------------------------------------------------------------------
    def do_GET(self) -> None:
        self.route()

    def do_HEAD(self) -> None:
        self.route()

    def do_POST(self) -> None:
        self.route()

    def route(self) -> None:
        app: App = self.server.app
        if self.watch is not None:
            if self.watch.expired:  # cut off while it was still sending its request: nothing to answer
                return
            if self.command != "POST":  # a POST's body is read before its deadline is relaxed (_form)
                self.server.reaper.relax(self.watch)
        if not app.requests.acquire(blocking=False):
            self.respond(503, webpages.error(503), [("Retry-After", "30")])
            return
        try:
            self._route(app)
        except Busy:
            self.respond(503, webpages.error(503), [("Retry-After", "30")])
        except Exception as e:  # a page that cannot be made: its type only, never a value, to the journal
            log(f"a page failed ({type(e).__name__})")
            with contextlib.suppress(Exception):
                self.respond(500, webpages.error(500))
        finally:
            app.requests.release()

    def _host_ok(self, app: App) -> bool:
        host = self.headers.get("Host")
        if host is None:
            return True  # an HTTP/1.0 client without Host names no other site
        name = host.strip().lower()
        if name.startswith("["):
            return False
        name = name.rsplit(":", 1)[0] if name.count(":") == 1 else name
        return name.rstrip(".") in app.hosts

    def _same_origin(self, app: App) -> bool:
        """A POST from this page itself: no Origin, or one naming this page; never a cross-site fetch."""
        if self.headers.get("Sec-Fetch-Site", "").lower() == "cross-site":
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        parts = urllib.parse.urlsplit(origin)
        return parts.scheme == "https" and (parts.hostname or "").rstrip(".") in app.hosts

    def _form(self) -> dict[str, str] | None:
        """The urlencoded body of a POST, or None after answering why it cannot be read."""
        if self.headers.get("Transfer-Encoding"):
            self.respond(411, webpages.error(411))
            return None
        length = self.headers.get("Content-Length", "")
        if not re.fullmatch(r"[0-9]{1,5}", length):  # ASCII digits only: `²` is a digit to str.isdigit
            self.respond(411, webpages.error(411))
            return None
        n = int(length)
        if n > MAX_BODY:
            self.close_connection = True
            self.respond(413, webpages.error(413))
            return None
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if ctype != "application/x-www-form-urlencoded":
            self.respond(415, webpages.error(415))
            return None
        raw = self.rfile.read(n)
        if self.watch is not None and not self.watch.expired:
            self.server.reaper.relax(self.watch)
        if len(raw) != n:
            self.respond(400, webpages.error(400))
            return None
        try:
            pairs = urllib.parse.parse_qsl(
                raw.decode("ascii"),
                keep_blank_values=True,
                max_num_fields=8,
                encoding="utf-8",
                errors="strict",
            )
        except (UnicodeDecodeError, ValueError):
            self.respond(400, webpages.error(400))
            return None
        return dict(pairs)

    def _route(self, app: App) -> None:
        target = self.path
        if (
            len(target) > MAX_PATH
            or not target.startswith("/")
            or target.startswith("//")
            or not target.isascii()
        ):
            self.respond(
                404 if len(target) <= MAX_PATH else 414,
                webpages.error(404 if len(target) <= MAX_PATH else 414),
            )
            return
        if not self._host_ok(app):
            self.respond(421, webpages.error(421))
            return
        path, _, query = target.partition("?")
        jar = _cookies(self.headers.get("Cookie"))
        stored = app.password()
        mark = webauth.mark(stored)
        session = app.sessions.get(jar.get(SESSION_COOKIE), app.clock(), mark) if stored else None
        method = "GET" if self.command == "HEAD" else self.command

        if path == "/style.css":
            if method != "GET":
                return self._not_allowed("GET, HEAD")
            return self.respond(200, webpages.STYLE, ctype="text/css")
        if path == "/login":
            if method == "POST":
                return self._sign_in(app, jar, stored, mark)
            if method != "GET":
                return self._not_allowed("GET, HEAD, POST")
            if session is not None:
                return self.redirect("/")
            return self._login_page(app)
        if path == "/logout":
            if method != "POST":
                return self._not_allowed("POST")
            return self._sign_out(app, jar, session)

        day_m = re.fullmatch(r"/day/(\d{4}-\d{2}-\d{2})(/full)?", path)
        name_m = re.fullmatch(r"/name/([^/]{1,512})", path)
        if not (path in PAGES or day_m or name_m):
            return self.respond(404, webpages.error(404, signed_in_csrf=session.csrf if session else None))
        if method != "GET":
            return self._not_allowed("GET, HEAD")
        if session is None:
            return self.redirect("/login")
        csrf = session.csrf
        if path == "/":
            return self._today(app, csrf)
        if path == "/rules":
            message, rows = rules_view(app.s, app.prof)
            return self.respond(200, webpages.rules(message, rows, csrf))
        if path == "/about":
            return self.respond(200, webpages.about(app.s.web_port, csrf))
        if path == "/name":
            q = urllib.parse.parse_qs(query, max_num_fields=4).get("q", [""])[0].strip().lower().rstrip(".")
            if webpages.NAME.fullmatch(q):
                return self.redirect(f"/name/{q}")
            return self.respond(
                404, webpages.error(404, "That is not a name the gateway could have seen.", csrf)
            )
        if day_m:
            return self._day(app, day_m.group(1), bool(day_m.group(2)), csrf)
        return self._name(app, name_m.group(1), csrf)

    def _not_allowed(self, allow: str) -> None:
        self.respond(405, webpages.error(405), [("Allow", allow)])

    # -- signing in and out ----------------------------------------------------------------------------
    def _login_page(
        self, app: App, message: str = "", code: int = 200, extra: list[tuple[str, str]] | None = None
    ) -> None:
        cookie = webauth.new_token()
        set_cookie = (
            f"{FORM_COOKIE}={cookie}; Max-Age={FORM_MAX_AGE}; Path=/; Secure; HttpOnly; SameSite=Strict"
        )
        self.respond(
            code,
            webpages.login(app.forms.issue(cookie), message),
            [("Set-Cookie", set_cookie), *(extra or [])],
        )

    def _sign_in(self, app: App, jar: dict[str, str], stored: str | None, mark: str) -> None:
        if not self._same_origin(app):
            return self.respond(403, webpages.error(403))
        form = self._form()
        if form is None:
            return None
        if not app.forms.check(jar.get(FORM_COOKIE), form.get("csrf")):
            return self._login_page(app, "The sign-in form had expired. Type the password again.", 403)
        if stored is None:
            return self._login_page(
                app, "No password is set. On the gateway, run sudo tvgw web password.", 503
            )
        known = app.devices.known(jar.get(DEVICE_COOKIE), stored)
        # reserved under the limiter's lock before the slow hash, so guesses sent together wait their turn
        ticket, wait = app.limiter.admit(self.client_address[0], known, app.clock())
        if ticket is None:
            words = _wait_words(wait)
            return self._login_page(
                app,
                f"Too many sign-ins for now. Wait {words}, then try again.",
                429,
                [("Retry-After", str(math.ceil(wait)))],
            )
        with app.checking:
            ok = webauth.check_password(form.get("password", ""), stored)
        if not ok:
            log("a sign-in failed")
            after = app.limiter.waiting(ticket, app.clock())
            if after:
                log(f"sign-ins from that address wait {_wait_words(after)}")
            if not known and app.limiter.unknown_full():
                log("sign-ins from devices the page does not know are refused for the rest of the day")
            return self._login_page(app, "That password is not right.", 403)
        app.limiter.succeeded(ticket)
        token, _ = app.sessions.open(app.clock(), mark)
        log("signed in")
        flags = "Path=/; Secure; HttpOnly; SameSite=Strict"
        cookies = [
            ("Set-Cookie", f"{SESSION_COOKIE}={token}; Max-Age={webauth.SESSION_ABSOLUTE}; {flags}"),
            ("Set-Cookie", f"{FORM_COOKIE}=; Max-Age=0; {flags}"),
        ]
        if not known:
            device = app.devices.issue(stored)
            cookies.append(("Set-Cookie", f"{DEVICE_COOKIE}={device}; Max-Age={DEVICE_MAX_AGE}; {flags}"))
        return self.redirect("/", cookies)

    def _sign_out(self, app: App, jar: dict[str, str], session) -> None:
        if not self._same_origin(app):
            return self.respond(403, webpages.error(403))
        form = self._form()
        if form is None:
            return None
        if session is None:
            return self.redirect("/login")
        token = form.get("csrf", "")
        if not webauth.TOKEN.fullmatch(token) or not hmac.compare_digest(token, session.csrf):
            return self.respond(403, webpages.error(403, signed_in_csrf=session.csrf))
        app.sessions.close(jar.get(SESSION_COOKIE))
        clear = f"{SESSION_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict"
        return self.redirect("/login", [("Set-Cookie", clear)])

    # -- the pages -------------------------------------------------------------------------------------
    def _today(self, app: App, csrf: str) -> None:
        from tvgw import plain, queries, status, verify

        lines, tier = status.lines(status.read_status(app.status_path or verify.STATUS), app.wall())
        brief = None
        none_yet = "The gateway has no record yet. The first brief is ready the morning after it starts."
        if os.path.exists(app.s.db_path):
            conn = open_store(app.s.db_path)
            try:
                day_ = (datetime.fromtimestamp(app.wall()) - timedelta(days=1)).strftime("%Y-%m-%d")
                if queries.first_ingest(conn) is not None:
                    plain_lines, _, _ = app.record.brief(conn, day_)
                    brief = webpages.brief_parts(day_, plain_lines, plain.NOTHING, plain.FOOTER)
            finally:
                conn.close()
        self.respond(200, webpages.today(lines, str(tier), brief, csrf, none_yet))

    def _day(self, app: App, day_: str, engineering: bool, csrf: str) -> None:
        from tvgw import plain

        try:
            d = date.fromisoformat(day_)
        except ValueError:
            return self.respond(404, webpages.error(404, signed_in_csrf=csrf))
        today_ = datetime.fromtimestamp(app.wall()).date()
        if d > today_:
            return self.respond(404, webpages.error(404, "That day has not come yet.", csrf))
        if not os.path.exists(app.s.db_path):
            return self.respond(404, webpages.error(404, "The gateway has no record yet.", csrf))
        conn = open_store(app.s.db_path)
        try:
            first = app.record.first(conn)
            start = datetime.fromtimestamp(first).date() if first is not None else None
            kept = today_ - timedelta(days=app.s.db_days)
            known = start is not None and start <= d and d >= kept
            prev = (d - timedelta(days=1)).isoformat()
            prev = prev if start is not None and date.fromisoformat(prev) >= max(start, kept) else None
            nxt = (d + timedelta(days=1)).isoformat() if d < today_ else None
            if engineering:
                if not known:
                    return self.respond(
                        404, webpages.error(404, "The gateway keeps no record of that day.", csrf)
                    )
                _, text, _ = app.record.brief(conn, day_)
                return self.respond(200, webpages.full(day_, text, csrf))
            brief, note, rows, news = None, "", [], []
            if known:
                lines, _, found = app.record.brief(conn, day_)
                brief = webpages.brief_parts(day_, lines, plain.NOTHING, plain.FOOTER)
                news = [self._new(app, x) for x in found[:NEW_SHOWN]]
            elif start is None:
                note = "The gateway has no record yet."
            else:
                begins = max(start, kept).isoformat()
                note = f"The gateway keeps no record of this day. Its record starts on {begins}."
            if start is not None:
                for i in range(TABLE_DAYS):
                    day_i = d - timedelta(days=i)
                    if day_i < max(start, kept):
                        break
                    rows.append(app.record.row(conn, day_i.isoformat()))
        finally:
            conn.close()
        self.respond(200, webpages.day(brief, day_, prev, nxt, rows, news, csrf, note))

    def _new(self, app: App, x: dict) -> webpages.NewName:
        from tvgw import companies, plain

        return webpages.NewName(
            name=x["name"],
            kind=plain.category_label(x["category"], app.prof),
            company=companies.company(x["name"]) if webpages.NAME.fullmatch(x["name"] or "") else None,
            blocked=bool(x["blocked"]) if x["blocked"] is not None else False,
        )

    def _name(self, app: App, raw: str, csrf: str) -> None:
        try:
            name = urllib.parse.unquote(raw, errors="strict").strip().lower().rstrip(".")
        except UnicodeDecodeError:  # `%ff`: no name the gateway could have seen
            name = ""
        if not webpages.NAME.fullmatch(name):
            return self.respond(
                404, webpages.error(404, "That is not a name the gateway could have seen.", csrf)
            )
        if not os.path.exists(app.s.db_path):
            return self.respond(404, webpages.error(404, "The gateway has no record yet.", csrf))
        conn = open_store(app.s.db_path)
        try:
            view = app.record.name(conn, name)
        finally:
            conn.close()
        self.respond(200 if view.seen or view.under else 404, webpages.name(view, csrf))


class _HeadLimit:
    """A connection's reader with its request line and headers held to `budget` bytes together: the
    standard library would take 100 header lines of 64 KB each. A line that would run past the budget raises
    LineTooLong, which the handler answers with 431, having read no more than the budget. The body, read
    with `read`, is the handler's to bound (MAX_BODY)."""

    def __init__(self, raw, budget: int):
        self._raw, self.left = raw, budget

    def readline(self, size: int | None = -1) -> bytes:
        cap = self.left + 1 if size is None or size < 0 else min(size, self.left + 1)
        line = self._raw.readline(cap)
        self.left -= len(line)
        if self.left < 0:
            raise http.client.LineTooLong("request head")
        return line

    def read(self, n: int = -1) -> bytes:
        return self._raw.read(n)

    def __getattr__(self, name: str):
        return getattr(self._raw, name)


class Watch:
    """One connection's deadline: the socket the reaper shuts when it passes, whatever the thread is
    waiting on, and whether it did."""

    def __init__(self, sock, deadline: float):
        self.sock, self.deadline = sock, deadline
        self.expired = self.done = False


class Reaper:
    """One thread that shuts each connection's socket at its deadline: a socket timeout bounds each read,
    and a client sending a byte or a header line just inside it (the TLS handshake included) would hold
    its thread for ever. REQUEST_DEADLINE from accept covers the handshake and the whole request;
    RESPONSE_DEADLINE more, once it is read, covers the page."""

    def __init__(self, clock: Callable[[], float] = time.monotonic, tick: float = 0.2):
        self.clock, self.tick = clock, tick
        self._heap: list[tuple[float, int, Watch]] = []
        self._n = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        threading.Thread(target=self._run, name="tvgw-web-reaper", daemon=True).start()

    def watch(self, sock, seconds: float) -> Watch:
        w = Watch(sock, self.clock() + seconds)
        self._push(w)
        return w

    def relax(self, w: Watch, seconds: float | None = None) -> None:
        """The request is read: from now, RESPONSE_DEADLINE (or `seconds`) to answer it."""
        w.deadline = self.clock() + (RESPONSE_DEADLINE if seconds is None else seconds)
        self._push(w)

    def done(self, w: Watch) -> None:
        w.done = True

    def stop(self) -> None:
        self._stop.set()

    def _push(self, w: Watch) -> None:
        with self._lock:
            self._n += 1
            heapq.heappush(self._heap, (w.deadline, self._n, w))

    def _run(self) -> None:
        while not self._stop.wait(self.tick):
            now = self.clock()
            due: list[Watch] = []
            with self._lock:
                while self._heap and self._heap[0][0] <= now:
                    deadline, _, w = heapq.heappop(self._heap)
                    if not w.done and deadline == w.deadline:  # an entry a relax replaced is stale
                        due.append(w)
            for w in due:
                w.expired = True
                with contextlib.suppress(OSError):
                    # the plain socket's shutdown, on the TLS socket too: the thread's read returns at once
                    socket.socket.shutdown(w.sock, socket.SHUT_RDWR)


class Server(ThreadingHTTPServer):
    """A threaded HTTP server that does each TLS handshake in the connection's own thread, under the
    socket timeout and the connection's deadline, so a slow client never holds up the next accept: at most
    MAX_CONNECTIONS at once, and MAX_PER_ADDRESS from one address."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address: tuple[str, int], app: App, ctx: ssl.SSLContext | None):
        self.app, self.ctx = app, ctx
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.local = threading.local()
        self.reaper = Reaper()
        self._per: dict[str, int] = {}
        self._per_lock = threading.Lock()
        super().__init__(address, Handler)

    def _take(self, address: str) -> bool:
        with self._per_lock:
            if self._per.get(address, 0) >= MAX_PER_ADDRESS:
                return False
            self._per[address] = self._per.get(address, 0) + 1
            return True

    def _give(self, address: str) -> None:
        with self._per_lock:
            left = self._per.get(address, 1) - 1
            if left > 0:
                self._per[address] = left
            else:
                self._per.pop(address, None)

    def process_request(self, request, client_address) -> None:
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        if not self._take(client_address[0]):
            self.slots.release()
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._give(client_address[0])
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        w = self.reaper.watch(request, REQUEST_DEADLINE)
        self.local.watch = w
        try:
            request.settimeout(SOCKET_TIMEOUT)
            if self.ctx is not None:
                # wrapping hands the descriptor to the TLS socket at once: the reaper is pointed at it
                # before the handshake, which a client sending a byte at a time would otherwise stretch
                try:
                    tls = self.ctx.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                except (OSError, ssl.SSLError, ValueError):
                    self.shutdown_request(request)
                    return
                w.sock = tls
                try:
                    tls.do_handshake()
                except (OSError, ssl.SSLError, ValueError):
                    self.shutdown_request(tls)
                    return
                request = tls
            super().process_request_thread(request, client_address)
        finally:
            self.reaper.done(w)
            self.local.watch = None
            self._give(client_address[0])
            self.slots.release()

    def server_close(self) -> None:
        self.reaper.stop()
        super().server_close()

    def handle_error(self, request, client_address) -> None:
        return  # a client that went away mid-response is not news for the journal


# ---- the commands --------------------------------------------------------------------------------------
Runner = Callable[[list[str]], str]


def run_cmd(cmd: list[str]) -> str:
    """stdout of a command, '' when it fails or is missing."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, check=False
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def serve(
    s: Settings,
    prof: Profile,
    *,
    euid: Callable[[], int] = os.geteuid,
    find: Callable[[str], str | None] = ipv4_of,
    ready: Callable[[Server], None] | None = None,
) -> int:
    """`tvgw web serve`, the unit's process: 0 and nothing served with WEB=off; 2 (which the unit does not
    restart) for what the owner must fix; 1 for an uplink without an address yet, which the unit retries."""
    if s.web != "on":
        log("WEB=off in the settings: nothing is served")
        return 0
    if euid() == 0:
        log("refuses to serve as root; its unit runs it as the tvgw-web user")
        return 2
    try:
        address = bind_address(s, find)
    except WebError as e:
        log(f"{e}; trying again later")
        return 1
    try:
        check_bind(address, s)
    except WebError as e:
        log(str(e))
        return 2
    if webauth.read_hash(s.web_password) is None:
        log("no password is set: run sudo tvgw web password")
        return 2
    try:
        ctx = tls_context(s.web_cert, s.web_key)
    except (OSError, ssl.SSLError) as e:
        log(f"the certificate could not be loaded ({type(e).__name__}): run sudo tvgw web cert")
        return 2
    app = App(s, prof, address)
    try:
        httpd = Server((address, s.web_port), app, ctx)
    except OSError as e:
        log(f"could not listen on port {s.web_port} ({e.strerror or type(e).__name__})")
        return 1
    stop = threading.Event()

    def on_term(signum, frame) -> None:
        if not stop.is_set():
            stop.set()
            threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    where = "loopback" if s.web_bind == "loopback" else "the uplink's address"
    log(f"started on {where}, port {s.web_port}")
    if ready is not None:
        ready(httpd)
    try:
        httpd.serve_forever(poll_interval=0.5)
    finally:
        httpd.server_close()
        log("stopped")
    return 0


def _write_owned(path: str, data: bytes, mode: int, gid: int) -> None:
    """A file beside `path`, fsynced, mode and owner set, then renamed over it: a power cut leaves either."""
    directory = os.path.dirname(path) or "."
    tmp = os.path.join(directory, f".{os.path.basename(path)}.new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chown(tmp, 0, gid)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _group_id() -> int:
    try:
        return grp.getgrnam(GROUP).gr_gid
    except KeyError:
        raise WebError("the tvgw-web user does not exist yet: run the installer first") from None


def make_cert(
    s: Settings,
    *,
    euid: Callable[[], int] = os.geteuid,
    run: Callable[[list[str]], subprocess.CompletedProcess] | None = None,
    find: Callable[[str], str | None] = ipv4_of,
    hostname: Callable[[], str] = socket.gethostname,
    gid: Callable[[], int] = _group_id,
    restart: Runner = run_cmd,
    out: Callable[[str], None] = print,
) -> int:
    """`sudo tvgw web cert`: a new key and self-signed certificate, the key 0640 root:tvgw-web, then the
    page restarted if it runs, so it serves the new one."""
    if euid() != 0:
        out("tvgw web cert: it writes the page's key in /etc/tvgw; run it with sudo: sudo tvgw web cert")
        return 1
    try:
        group = gid()
    except WebError as e:
        out(f"tvgw web cert: {e}")
        return 1
    address = None if s.web_bind == "loopback" else find(s.wan_if)
    names, ips = cert_names(hostname(), address)
    key_tmp = os.path.join(os.path.dirname(s.web_key), ".web-key.pem.openssl")
    cert_tmp = os.path.join(os.path.dirname(s.web_cert), ".web-cert.pem.openssl")
    old = os.umask(0o077)  # openssl writes the key with this mask: never readable by others, even briefly
    try:
        for leftover in (key_tmp, cert_tmp):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(leftover)
        cmd = openssl_command(key_tmp, cert_tmp, names, ips)
        runner = run or (lambda c: subprocess.run(c, capture_output=True, text=True, check=False, timeout=60))
        try:
            done = runner(cmd)
        except (OSError, subprocess.TimeoutExpired) as e:
            out(f"tvgw web cert: openssl could not be run ({type(e).__name__}): install the openssl package")
            return 1
        if done.returncode != 0:
            why = (done.stderr or "").strip().splitlines()[-1:] or ["no reason given"]
            out(f"tvgw web cert: openssl failed: {why[0]}")
            return 1
        with open(key_tmp, "rb") as fh:
            key = fh.read()
        with open(cert_tmp, "rb") as fh:
            cert = fh.read()
    finally:
        os.umask(old)
        for leftover in (key_tmp, cert_tmp):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(leftover)
    _write_owned(s.web_key, key, 0o640, group)
    _write_owned(s.web_cert, cert, 0o644, 0)
    fp = fingerprint(cert.decode("ascii", errors="replace"))
    ends = cert_end(s.web_cert, run_cmd)
    until = datetime.fromtimestamp(ends).strftime("%Y-%m-%d") if ends else f"{CERT_DAYS} days from now"
    out(f"Made a new certificate for the page, valid until {until}.")
    out(f"It names: {', '.join(names + ips)}")
    out("Its SHA-256 fingerprint:")
    out(f"  {fp}")
    out(
        "Your phone's browser warns about it once, because the gateway made it itself. Compare the"
        " fingerprint the warning page shows with the one above; when they are the same, go on."
    )
    restart(["systemctl", "try-restart", f"{UNIT}.service"])
    return 0


def set_password(
    s: Settings,
    *,
    euid: Callable[[], int] = os.geteuid,
    ask: Callable[[str], str] | None = None,
    tty: Callable[[], bool] = lambda: sys.stdin.isatty(),
    gid: Callable[[], int] = _group_id,
    restart: Runner = run_cmd,
    out: Callable[[str], None] = print,
) -> int:
    """`sudo tvgw web password`: asks twice, stores the scrypt hash 0640 root:tvgw-web, and restarts the
    page if it runs, which signs everyone out."""
    if euid() != 0:
        out(
            "tvgw web password: it writes the page's password in /etc/tvgw; run it with sudo:"
            " sudo tvgw web password"
        )
        return 1
    if ask is None:
        if not tty():
            out("tvgw web password: it asks for the password at a terminal; run it in one")
            return 1
        import getpass

        ask = getpass.getpass
    try:
        group = gid()
    except WebError as e:
        out(f"tvgw web password: {e}")
        return 1
    first = ask(f"New password for the page (at least {webauth.MIN_PASSWORD} characters): ")
    problem = webauth.password_problem(first)
    if problem:
        out(f"{problem} Nothing was changed.")
        return 1
    if ask("The same password again: ") != first:
        out("The two passwords differ. Nothing was changed.")
        return 1
    _write_owned(s.web_password, (webauth.hash_password(first) + "\n").encode("ascii"), 0o640, group)
    out(f"Saved in {s.web_password}, as a hash. Anyone signed in to the page is signed out.")
    restart(["systemctl", "try-restart", f"{UNIT}.service"])
    return 0


def status_lines(
    s: Settings,
    run: Runner = run_cmd,
    read: Callable[[str], str] | None = None,
    hostname: Callable[[], str] = socket.gethostname,
    now: float | None = None,
) -> list[str]:
    """`sudo tvgw web status`: whether the page runs and where, its certificate's fingerprint and end, and
    whether a password is set."""
    from tvgw import verify

    read = read or verify.read_file
    now = time.time() if now is None else now
    active = run(["systemctl", "is-active", f"{UNIT}.service"]).strip() == "active"
    heard = tcp_listeners(read("/proc/net/tcp"), read("/proc/net/tcp6"), s.web_port)
    out = []
    if s.web != "on":
        out.append(
            f"The page is off (WEB=off). {'It still runs: ' if active else ''}"
            + ("sudo systemctl disable --now tvgw-web stops it." if active else "Nothing serves it.")
        )
    else:
        out.append(
            "The page is on (WEB=on), and it runs."
            if active
            else "The page is on (WEB=on), but it does not run: see systemctl status tvgw-web."
        )
    if heard:
        where = ", ".join(sorted(set(heard)))
        out.append(f"Port {s.web_port} is open on: {where}.")
        host = hostname()
        urls = [f"https://{a}:{s.web_port}/" for a in sorted(set(heard)) if a not in ("0.0.0.0", "::")]
        if _HOSTNAME.fullmatch(host or "") and s.web_bind == "uplink":
            urls.insert(0, f"https://{host.lower()}.local:{s.web_port}/")
        if urls and s.web == "on":
            out.append("Open it at: " + " or ".join(urls))
    else:
        out.append(f"Nothing listens on port {s.web_port}.")
    try:
        with open(s.web_cert, encoding="ascii", errors="replace") as fh:
            fp = fingerprint(fh.read())
    except OSError:
        fp = None
    if fp is None:
        out.append("There is no certificate yet: sudo tvgw web cert makes one.")
    else:
        out.append(f"The certificate's SHA-256 fingerprint: {fp}")
        ends = cert_end(s.web_cert, run)
        if ends is not None:
            days = int((ends - now) // 86400)
            until = datetime.fromtimestamp(ends).strftime("%Y-%m-%d")
            out.append(
                f"It is valid until {until} ({days} days)."
                if days >= 0
                else f"It ended on {until}: sudo tvgw web cert makes a new one."
            )
    try:
        with open(s.web_password, encoding="utf-8") as fh:
            stored = fh.read(4096)
        set_ = webauth.parse_hash(stored) is not None
        out.append("A password is set." if set_ else "No password is set: sudo tvgw web password sets one.")
    except FileNotFoundError:
        out.append("No password is set: sudo tvgw web password sets one.")
    except OSError:
        out.append("Whether a password is set cannot be read from this account: run it with sudo.")
    return out


def main(action: str, s: Settings, prof: Profile) -> int:
    if action == "serve":
        return serve(s, prof)
    if action == "cert":
        return make_cert(s)
    if action == "password":
        return set_password(s)
    if action == "status":
        for line in status_lines(s):
            print(line)
        return 0
    if action == "dropin":
        sys.stdout.write(dropin(s))
        return 0
    raise ValueError(action)
