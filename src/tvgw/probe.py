"""`tvgw probe`: would the TV work right now, and do the walls hold? A test client where the TV stands.

The TV is cabled straight to TV_IF and is off for most of every day, so nothing on that wire can say
whether a change the gateway made to itself left the TV's path working (design decision 65). The probe
is a client the gateway makes for a few seconds: a network namespace joined to the gateway by a veth
pair, with an address of its own in TV_NET (TV_PROBE_IP). `tvgw-apply` gives the pair's gateway end
(GW_IF) a twin of every rule the TV's packets cross, made from the text of the TV's own chains at each
apply, without their counters, logs and comments. The client then does what the TV does:

- it asks the gateway's resolver for a name the profile says must work, and must get an address. It
  never connects to that address: the probe makes no connection to the TV's vendor, ever;
- when a connection out is due, it completes a TLS handshake with a neutral server (TV_PROBE_TARGET, or
  the host one of the profile's blocklists is fetched from), through the forward path, the address
  translation and the uplink, and back. No request is sent, and the certificate is not judged: the path is;
- it asks for a name the profile blocks, and must be refused;
- it tries DNS over TLS (TCP 853) and, with BLOCK_QUIC=yes, QUIC (UDP 443), and must be refused;
- it aims a lookup of the blocked name at a public resolver, and must still be refused, which shows the
  gateway's filter answered it.

Beside those packets it reads what no packet of its own can cross: the forwarding switch of the TV's own
port and the kernel's route for a packet from the TV's address arriving there ("asked, not crossed").

A failure of the lookup or of the connection out is `fail` only when the gateway's own reading says the
fault is on the TV's path: its uplink has carrier and an address, and the gateway itself reaches what
the probe could not. Otherwise the verdict is `unknown`, which never undoes anything.

What it shares with the TV for real: the resolver, the URL filter's listeners, routing rule 60 and
table 100 (both chosen by source address), connection tracking, the uplink. What it crosses as a twin:
the filter chains, the DNS redirect, the masquerade. What it cannot cross: the cable, the TV's DHCP lease,
TV_IF's own kernel switches (read instead), a rule put into the TV's chains by hand after the apply
(`tvgw verify`'s ruleset_unchanged sees that), anything keyed on the TV's own address (the HTTPS-record
strip), and everything that records: the capture, the flow log and the DNS gate are not twinned, which
is also why the probe is in none of them.

Everything that decides is a pure function of what was observed (`judge`); every command and file is a
parameter (`Env`), so the logic is tested away from a gateway. The client half runs inside the namespace
as `python -m tvgw.probe --client`.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import ipaddress
import json
import os
import select
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from tvgw import config, dnsmsg, dnsq
from tvgw.config import Settings
from tvgw.profile import Profile

NETNS = "tvgw-probe"  # the namespace, made and removed by each run
GW_IF = "tvgw-probe"  # the pair's gateway end: the name tvgw-apply's probe rules match (PROBE_IF there)
NS_IF = "tvgw-probe0"  # the client's end
# both ends' hardware addresses, locally administered and fixed: given at creation, so udev's
# MACAddressPolicy leaves them alone and the two static neighbour entries below never go stale
GW_MAC, NS_MAC = "02:74:76:67:77:01", "02:74:76:67:77:02"
CHAIN = "probe_fwd"  # the chain whose presence says the loaded firewall has a place for the probe
LOCK = "/run/lock/tvgw-probe.lock"
LOCK_WAIT = 20.0  # seconds a run waits for another run's namespace before it says unknown
PASS, FAIL, UNKNOWN, SKIPPED = "pass", "fail", "unknown", "skipped"
# `tvgw probe`'s exit status. A failure is never 1 or 2: an uncaught error exits 1 and a usage error 2,
# and tvgw-apply reads everything but 0 and 3 as unknown
EXIT = {PASS: 0, FAIL: 3, UNKNOWN: 4}
MAX_ALLOW = 2  # must-allow names asked for before the lookup is given up
MAX_TARGETS = 2  # neutral servers tried before the connection out is given up
# The connection out leaves the home, so the 10-minute check makes it four times a day and not 144: what
# it adds to the steps that never leave the gateway (the port, the lookups, the walls, which already cross
# the forward chain and the routing rule) is the address translation, the uplink and the way back, and a
# fault there comes from an apply, which is confirmed with a connection of its own, or from outside the
# gateway. One that did not pass is looked at again within the hour. `sudo tvgw probe` always makes it.
PATH_EVERY, PATH_RETRY = 6 * 3600, 3600
APPLIED = "/run/tvgw/settings.applied"  # the settings the loaded firewall and routes were applied with
# the keys of it that say what the live gateway is: the probe judges that, not what the file says next
LIVE_KEYS = ("UPLINK", "WAN_IF", "VPN_IF", "TV_IF", "TV_NET", "GW_IP", "TV_IP", "BLOCK_QUIC", "TV_PROBE_IP")
PATH_STAMP = "/run/tvgw/probe.path"  # `<epoch> <outcome>` of the last connection out
DNS_TIMEOUT, TCP_TIMEOUT, UDP_TIMEOUT = 2.0, 3.0, 1.2
# the whole client. Its longest run is every wait above with nothing answering: MAX_ALLOW lookups,
# MAX_TARGETS lookups and handshakes, the walls: 2 x 2 + 2 x (2 + 3) + 2 + 3 + 2 x 1.2 + 2, under 24
# seconds. tvgw-apply's own waits are sized on it: 30 seconds for the verdict before (one observation)
# and 60 for the one after (two, RETRY_PAUSE apart, and HOLD_SETTLE), which with the apply itself stays
# inside tvgw.service's two-minute start
CLIENT_TIMEOUT = 26.0
RETRY_PAUSE = 2.0  # a failed verdict is taken again once, this much later, before it stands
HOLD_SETTLE = 2.2  # seconds after a re-apply before the held connection is judged: two keep-alives
HOLD_MAX = 90.0  # the longest the holder waits for the apply it brackets
DEFAULT_RESOLVER = "1.1.1.1"  # the public resolver the walls are tried against, when DNS_BOOTSTRAP names none
# a long-header packet of a version no server speaks (0x?a?a?a?a is reserved to force negotiation, RFC
# 9000 section 15), padded to 1200 bytes: a QUIC server that received it must answer, so "it got through"
# can be seen and not only "nothing refused it"
# tvgw-apply's lan4 set, loopback and the reserved top of the space
_NOT_OUTSIDE = tuple(
    ipaddress.IPv4Network(n)
    for n in ("10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
              "192.168.0.0/16", "240.0.0.0/4")
)  # fmt: skip
QUIC_PROBE = (b"\xc0\x1a\x2a\x3a\x4a\x08tvgwprob\x00" + bytes(1200))[:1200]


# ---- what a run plans, sees and concludes ---------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    """What one run asks: fixed before any packet is sent, from the settings and the profile alone."""

    gw_ip: str
    probe_ip: str
    allow: tuple[str, ...]  # must-allow names, in the profile's order, at most MAX_ALLOW: looked up only
    block: str | None  # a name the profile blocks: its first plain rule's, else a list's sentinel
    resolver: str  # a public resolver's address: the target of the DoT, QUIC and redirect stages
    quic: bool  # BLOCK_QUIC=yes: QUIC must be refused
    # neutral servers for the connection out, at most MAX_TARGETS: TV_PROBE_TARGET, else the hosts the
    # profile's blocklists are fetched from, which the gateway's own software already asks every day
    targets: tuple[str, ...] = ()

    def spec(self, connect: bool = True) -> dict:
        """What the client is handed. Without `connect` it gets no target and makes no connection out."""
        return {
            "gw": self.gw_ip,
            "allow": list(self.allow),
            "block": self.block,
            "resolver": self.resolver,
            "quic": self.quic,
            "targets": list(self.targets) if connect else None,
        }


@dataclass(frozen=True)
class Stage:
    name: str
    outcome: str  # PASS, FAIL, UNKNOWN or SKIPPED
    detail: str = ""


@dataclass
class Verdict:
    verdict: str  # PASS, FAIL or UNKNOWN
    stages: list[Stage] = field(default_factory=list)
    t: float = 0.0
    ms: int = 0

    @property
    def reason(self) -> str:
        """The first stage that decided the verdict, as `name: detail`; '' for a pass."""
        for s in self.stages:
            if s.outcome == self.verdict and self.verdict != PASS:
                return f"{s.name}: {s.detail}" if s.detail else s.name
        return ""

    @property
    def word(self) -> str:
        """The deciding stage's name alone: a plain word for the change ledger's spool."""
        return next((s.name for s in self.stages if s.outcome == self.verdict and self.verdict != PASS), "")

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "t": self.t,
            "ms": self.ms,
            "stages": [{"name": s.name, "outcome": s.outcome, "detail": s.detail} for s in self.stages],
        }

    def compact(self) -> str:
        """What the gateway sample stores: the verdict, the stage that decided it and each stage's
        outcome. No name, no address and no time of anything the TV did: nothing here is a viewing record."""
        return json.dumps(
            {
                "v": self.verdict,
                "why": self.word,
                "ms": self.ms,
                "s": {s.name: s.outcome for s in self.stages},
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def unknown(why: str, t: float | None = None) -> Verdict:
    """A run that could not judge: one stage, `probe`, saying why."""
    return Verdict(UNKNOWN, [Stage("probe", UNKNOWN, why)], t=time.time() if t is None else t)


def list_hosts(profile: Profile) -> list[str]:
    """The hosts the profile's blocklists are fetched from, in its order, each once; never an address."""
    out: list[str] = []
    for _name, url in profile.adguard_filters:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        with contextlib.suppress(ValueError):
            ipaddress.ip_address(host)
            continue
        if host and host not in out:
            out.append(host)
    return out


def plan(s: Settings, profile: Profile) -> Plan:
    """The names and the address a run uses. Raises ValueError when TV_PROBE_IP cannot be used."""
    from tvgw import adguardcfg, verify  # both import heavily; neither is needed by the client half

    filtered = set(profile.url_filter.hosts) if profile.url_filter else set()
    allow = tuple(h for h in profile.must_allow if h not in filtered and "*" not in h)[:MAX_ALLOW]
    block = adguardcfg._locally_blocked(profile.adguard_rules(s.gw_ip, s.tv_ip))
    if block is None:
        block = next(iter(verify.sentinels(profile)), None)
    resolver = DEFAULT_RESOLVER
    for item in s.dns_bootstrap.split(","):
        with contextlib.suppress(ValueError):
            ip = ipaddress.IPv4Address(item.strip())
            # an address the TV could be sent to: not the home LAN's ranges, which the filter drops in
            # silence before any wall is reached, and nothing that is no host on the internet
            if not (any(ip in n for n in _NOT_OUTSIDE) or ip.is_multicast or ip.is_unspecified):
                resolver = str(ip)
                break
    # never a name of the TV's vendor: a must-allow host is not a neutral server, whoever names it
    named = [s.tv_probe_target.lower()] if s.tv_probe_target else list_hosts(profile)
    targets = tuple(h for h in named if h not in profile.must_allow and h not in filtered)[:MAX_TARGETS]
    return Plan(s.gw_ip, config.probe_side(s), allow, block, resolver, s.block_quic == "yes", targets)


def _blocked(answers: list[str] | None) -> bool:
    """An answer that hands out no address: 0.0.0.0, or nothing (AdGuard's nxdomain and refused modes)."""
    return answers is not None and all(a == "0.0.0.0" for a in answers)


def _address(answers: list[str] | None) -> str | None:
    return next((a for a in answers or [] if a != "0.0.0.0"), None)


@dataclass(frozen=True)
class Port:
    """The TV's own port, read and asked: TV_IF's forwarding switches and the kernel's route for a packet
    from TV_IP arriving on TV_IF."""

    forwarding: bool
    route_dev: str | None
    out_if: str


@dataclass(frozen=True)
class Uplink:
    up: bool
    why: str = ""


def judge(
    p: Plan,
    obs: dict,
    port: Port,
    uplink: Uplink,
    control: Callable[[], dict[str, bool]] | None = None,
    held: Stage | None = None,
) -> Verdict:
    """The verdict of one observation. `control()` is asked only when the lookup or the connection out
    failed with the uplink up: it says whether the gateway itself did what the probe could not (`lookup`,
    `path`) and whether the resolver answers the gateway at all (`resolver`). A failure is the TV's path
    only when it did."""
    stages: list[Stage] = []
    did: dict[str, bool] | None = None

    def gateway() -> dict[str, bool]:
        nonlocal did
        if did is None:
            did = dict(control()) if control else {}
        return did

    # 1. the TV's own port: asked, not crossed
    if not port.forwarding:
        stages.append(Stage("port", FAIL, "forwarding is off for the TV's port"))
    elif port.route_dev != port.out_if:
        why = f"the TV's packets would leave by {port.route_dev or 'nothing'}, not {port.out_if}"
        stages.append(Stage("port", FAIL if uplink.up else UNKNOWN, why if uplink.up else uplink.why))
    else:
        stages.append(Stage("port", PASS))
    # 2. a must-allow name gets an address from the gateway's resolver; no connection is made to it
    asked = obs.get("allow") or []
    tried = obs.get("path")
    resolver_alive = obs.get("blocked") is not None or any(
        t.get("answers") is not None for t in [*asked, *(tried or [])]
    )
    if not p.allow:
        stages.append(Stage("lookup", SKIPPED, "the profile names no must-allow host"))
    elif any(_address(t.get("answers")) for t in asked):
        stages.append(Stage("lookup", PASS))
    elif any(t.get("answers") and _blocked(t.get("answers")) for t in asked):
        stages.append(Stage("lookup", FAIL, "the filter blocks a must-allow name"))
    elif not uplink.up:
        stages.append(Stage("lookup", UNKNOWN, uplink.why))
    elif gateway().get("lookup"):
        why = "a must-allow lookup fails from the TV's position and works from the gateway itself"
        stages.append(Stage("lookup", FAIL, why))
    elif not resolver_alive and gateway().get("resolver") is True:
        why = "the resolver answers the gateway itself and not the TV's position"
        stages.append(Stage("lookup", FAIL, why))
    elif not resolver_alive and gateway().get("resolver") is False:
        stages.append(Stage("lookup", FAIL, "the gateway's resolver does not answer"))
    else:
        why = "a must-allow lookup fails, and from the gateway itself too: the resolver's upstream"
        stages.append(Stage("lookup", UNKNOWN, why))
    # 3. a connection out and back, to a neutral server
    if tried is None:
        stages.append(Stage("path", SKIPPED, "no connection out was due in this run"))
    elif not p.targets:
        stages.append(Stage("path", SKIPPED, "no neutral server is known: name one with TV_PROBE_TARGET"))
    elif any(t.get("tls") == "ok" for t in tried):
        stages.append(Stage("path", PASS))
    elif not uplink.up:
        stages.append(Stage("path", UNKNOWN, uplink.why))
    elif tried and all(t.get("ruled") or (t.get("answers") and _blocked(t.get("answers"))) for t in tried):
        why = "the filter or the firewall refuses the probe's own target: name another with TV_PROBE_TARGET"
        stages.append(Stage("path", UNKNOWN, why))
    elif gateway().get("path"):
        why = "a connection out fails from the TV's position and works from the gateway itself"
        stages.append(Stage("path", FAIL, why))
    else:
        why = "a connection out fails, and from the gateway itself too: the internet, not the TV's path"
        stages.append(Stage("path", UNKNOWN, why))
    # 4. the walls
    if p.block is None:
        stages.append(Stage("blocked", SKIPPED, "the profile names no blocked name"))
    else:
        got = obs.get("blocked")
        if got is None:
            stages.append(Stage("blocked", UNKNOWN, "the resolver gave no answer"))
        elif _blocked(got):
            stages.append(Stage("blocked", PASS))
        else:
            stages.append(Stage("blocked", FAIL, "the resolver answered a blocked name with an address"))
    stages.append(_wall("dot", obs.get("dot"), "DNS over TLS", uplink))
    if p.quic:
        stages.append(_wall("quic", obs.get("quic"), "QUIC", uplink))
    if p.block is not None:
        got = obs.get("redirect")
        if got is None:
            stages.append(Stage("redirect", UNKNOWN, "a lookup aimed at a public resolver got no answer"))
        elif _blocked(got):
            stages.append(Stage("redirect", PASS))
        else:
            why = "a lookup aimed at a public resolver was not answered by the gateway's filter"
            stages.append(Stage("redirect", FAIL, why))
    if held is not None:
        stages.append(held)
    outcomes = {s.outcome for s in stages}
    verdict = FAIL if FAIL in outcomes else UNKNOWN if UNKNOWN in outcomes else PASS
    return Verdict(verdict, stages)


def _wall(name: str, saw: str | None, what: str, uplink: Uplink) -> Stage:
    """A wall that answers with a refusal. Getting through is the failure. Silence is a wall that held
    without saying so for TCP, where a listener would have answered; for a datagram it proves nothing."""
    if saw == "refused":
        return Stage(name, PASS)
    if saw in ("connected", "answered"):
        return Stage(name, FAIL, f"{what} got through")
    if saw == "silent" and name == "dot":
        return Stage(name, PASS, "dropped, not refused")
    return Stage(name, UNKNOWN, uplink.why if not uplink.up else f"{what} was neither refused nor answered")


# ---- the client: what runs inside the namespace (and, for the control, in the gateway's own) ------------


def ask(name: str, server: str, timeout: float = DNS_TIMEOUT) -> list[str] | None:
    """The A records `server` gives for `name` over UDP, [] for an answer without one, None for none at
    all. The socket is connected, so only `server`'s reply is taken."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((server, 53))
            sock.send(dnsq.question(name, qid=int.from_bytes(os.urandom(2), "big")))
            data = sock.recv(4096)
    except OSError:
        return None
    try:
        return [a.value for a in dnsmsg.decode_answers(data) if a.rtype == "A"]
    except (ValueError, IndexError, struct.error):
        return []


def _saw(exc: BaseException) -> str:
    """One word for how a connection attempt ended."""
    if isinstance(exc, TimeoutError):
        return "silent"
    code = exc.errno if isinstance(exc, OSError) else None
    if code in (errno.ECONNREFUSED, errno.ECONNRESET):
        return "refused"
    if code in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT):
        return "silent" if code == errno.ETIMEDOUT else "unreachable"
    return "error"


def tcp_try(addr: str, port: int, timeout: float = TCP_TIMEOUT) -> str:
    """connected, refused, silent, unreachable or error."""
    try:
        with socket.create_connection((addr, port), timeout=timeout):
            return "connected"
    except (OSError, TimeoutError) as e:
        return _saw(e)


def udp_try(addr: str, port: int, payload: bytes, timeout: float = UDP_TIMEOUT) -> str:
    """answered, refused, silent, unreachable or error. A refusal (an ICMP error) surfaces on the
    connected socket's next call; silence is asked once more, since the kernel may hold back one ICMP
    error in a burst."""
    saw = "silent"
    for _ in range(2):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect((addr, port))
                sock.send(payload)
                sock.recv(2048)
                return "answered"
        except (OSError, TimeoutError) as e:
            saw = _saw(e)
            if saw != "silent":
                return saw
    return saw


def tls_context() -> ssl.SSLContext:
    """A client that completes a handshake with whatever the far end offers: the probe tests the path,
    and a TV's own servers need not satisfy this computer's trust store or its minimum protocol."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(ValueError, ssl.SSLError):
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


def handshake(addr: str, name: str, timeout: float = TCP_TIMEOUT) -> tuple[str, ssl.SSLSocket | None]:
    """A TLS handshake with `addr`, naming `name`: ('ok', the open socket) or (how it ended, None).
    Nothing is sent after the handshake."""
    try:
        raw = socket.create_connection((addr, 443), timeout=timeout)
    except (OSError, TimeoutError) as e:
        return _saw(e), None
    try:
        return "ok", tls_context().wrap_socket(raw, server_hostname=name)
    except (OSError, TimeoutError, ValueError) as e:  # ssl.SSLError is an OSError
        raw.close()
        return ("tls" if isinstance(e, ssl.SSLError) else _saw(e)), None


def observe(spec: dict, keep: bool = False) -> tuple[dict, ssl.SSLSocket | None]:
    """Everything one run sends, in order, and what came back. A must-allow name is looked up and never
    connected to. The connection out goes to the spec's `targets`, neutral servers; `targets` None is a
    run that makes none. With `keep` that connection is returned open (for the hold); otherwise it is
    closed as soon as the handshake is done."""
    gw, held = spec["gw"], None
    obs: dict = {"allow": [], "path": None}
    for name in spec["allow"]:
        answers = ask(name, gw)
        obs["allow"].append({"name": name, "answers": answers})
        if _address(answers):
            break
    if spec.get("targets") is not None:
        obs["path"] = []
        for name in spec["targets"]:
            answers = ask(name, gw)
            item: dict = {"name": name, "answers": answers, "addr": _address(answers), "tls": None}
            if item["addr"]:
                item["tls"], sock = handshake(item["addr"], name)
                if sock is not None and keep and held is None:
                    held = sock
                elif sock is not None:
                    sock.close()
            obs["path"].append(item)
            if item["tls"] == "ok":
                break
    block = spec.get("block")
    obs["blocked"] = ask(block, gw) if block else None
    obs["dot"] = tcp_try(spec["resolver"], 853)
    obs["quic"] = udp_try(spec["resolver"], 443, QUIC_PROBE) if spec.get("quic") else None
    obs["redirect"] = ask(block, spec["resolver"]) if block else None
    return obs, held


def _peer_state(sock: ssl.SSLSocket) -> str:
    """open, closed (the far end ended it) or reset. Whatever the far end sent after its handshake (its
    session tickets) is read away on the way: an end of the stream may sit behind it."""
    try:
        sock.settimeout(0)
        while True:
            if not sock.recv(4096):
                return "closed"
    except (ssl.SSLWantReadError, BlockingIOError):
        return "open"
    except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
        return "closed"
    except OSError:
        return "reset"


def client_main(argv: list[str]) -> int:
    """`python -m tvgw.probe --client SPEC [--hold SECONDS]`: one line of JSON per observation. With
    --hold it keeps the allowed connection open, with a keep-alive each second so that packets of it are
    in flight, waits for a line on stdin (the plan to observe next, as JSON), and observes
    again; no line in time, and it just ends."""
    spec = json.loads(argv[0])
    hold = float(argv[2]) if len(argv) >= 3 and argv[1] == "--hold" else 0.0
    obs, held = observe(spec, keep=hold > 0)
    first: dict = {"obs": obs}
    if held is not None:
        raw = held
        with contextlib.suppress(OSError, AttributeError):
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 30)
        first["held"] = {"dst": held.getpeername()[0], "sport": held.getsockname()[1]}
    print(json.dumps(first), flush=True)
    if hold <= 0:
        return 0
    ready, _, _ = select.select([sys.stdin], [], [], hold)
    line = sys.stdin.readline().strip() if ready else ""
    if not line:
        return 0
    # the line is what to observe now: the plan as the apply left it
    with contextlib.suppress(ValueError, AttributeError):
        spec = json.loads(line).get("spec") or spec
    state = _peer_state(held) if held is not None else None
    obs, _ = observe(spec)
    print(json.dumps({"obs": obs, "held_state": state}), flush=True)
    return 0


# ---- the gateway's side: its own readings, the namespace, the run ---------------------------------------


def _run(cmd: list[str], timeout: float = 15.0) -> tuple[int, str]:
    """(exit status, stdout); 127 for a command that is missing or does not finish."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
        )
        return out.returncode, out.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _write(path: str, text: str) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return True
    except OSError:
        return False


@dataclass
class Env:
    """Everything a run touches outside itself. `netns` is the namespace's name: a second gateway on the
    same computer (the namespace tier's) names its own."""

    run: Callable[..., tuple[int, str]] = _run
    read: Callable[[str], str] = _read
    write: Callable[[str, str], bool] = _write
    netns: str = NETNS
    python: str = sys.executable
    lock: str = LOCK
    sleep: Callable[[float], None] = time.sleep
    euid: Callable[[], int] = os.geteuid
    stamp: str = PATH_STAMP
    applied: str = APPLIED


def _json(text: str):
    try:
        return json.loads(text) if text.strip() else None
    except ValueError:
        return None


def live(s: Settings, env: Env) -> Settings:
    """`s` with the firewall's settings as the last apply used them (tvgw-apply's settings.applied). The
    probe judges the gateway as it is. The settings file may already say something else: an edit nobody
    applied yet, or the file of the very apply the probe is asked to stand before, which is about to move
    the TV to another uplink; judged by that file, a working gateway would read as broken. Without the
    record (nothing applied since boot) `s` stands, and the probe finds no rules of its own."""
    try:
        used = config.parse_conf(env.read(env.applied))
    except ValueError:
        return s
    changes = {config.CONF_KEYS[k]: used[k] for k in LIVE_KEYS if used.get(k)}
    return replace(s, **changes) if changes else s


def read_uplink(s: Settings, env: Env) -> Uplink:
    """The gateway's own reading of its uplink: the interface the TV leaves by exists, has carrier and an
    IPv4 address, and in vpn mode the home network's interface under the tunnel has carrier too."""

    def exists(dev: str) -> bool:
        return env.read(f"/proc/sys/net/ipv4/conf/{dev}/forwarding") != ""

    out_if = config.uplink_interface(s, exists)
    for dev in dict.fromkeys((out_if, s.wan_if)):
        if not exists(dev):
            return Uplink(False, f"the uplink is down: {dev} does not exist")
        if env.read(f"/sys/class/net/{dev}/carrier").strip() != "1":
            return Uplink(False, f"the uplink is down: {dev} has no carrier")
    links = _json(env.run(["ip", "-j", "-4", "addr", "show", "dev", out_if])[1]) or []
    for link in links if isinstance(links, list) else []:
        for a in link.get("addr_info", []) if isinstance(link, dict) else []:
            if isinstance(a, dict) and a.get("family") == "inet" and a.get("scope") == "global":
                return Uplink(True)
    return Uplink(False, f"the uplink is down: {out_if} has no IPv4 address")


def read_port(s: Settings, p: Plan, env: Env) -> Port:
    def exists(dev: str) -> bool:
        return env.read(f"/proc/sys/net/ipv4/conf/{dev}/forwarding") != ""

    on = all(
        env.read(path).strip() == "1"
        for path in ("/proc/sys/net/ipv4/ip_forward", f"/proc/sys/net/ipv4/conf/{s.tv_if}/forwarding")
    )
    route = _json(env.run(["ip", "-j", "route", "get", p.resolver, "from", s.tv_ip, "iif", s.tv_if])[1]) or []
    dev = route[0].get("dev") if isinstance(route, list) and route and isinstance(route[0], dict) else None
    return Port(on, dev if isinstance(dev, str) else None, config.uplink_interface(s, exists))


def control(p: Plan, obs: dict) -> dict[str, bool]:
    """What the gateway itself can do of what the probe could not, from its own network stack: `lookup`,
    a must-allow name gets an address; `path`, a target the probe could not reach is reached (its lookup
    when the probe got no address, else the handshake with the address the probe got); `resolver`, the
    resolver answers the gateway anything at all. Only what the probe failed at is tried."""
    did: dict[str, bool] = {}
    asked = obs.get("allow") or []
    if asked and not any(_address(a.get("answers")) for a in asked):
        did["lookup"] = any(_address(ask(a["name"], p.gw_ip)) is not None for a in asked)
    tried = obs.get("path") or []
    if tried and not any(t.get("tls") == "ok" for t in tried):
        did["path"] = False
        for item in tried:
            addr = _address(item.get("answers"))
            if addr is None:
                reached = _address(ask(item["name"], p.gw_ip)) is not None
            else:
                state, sock = handshake(addr, item["name"])
                if sock is not None:
                    sock.close()
                reached = state == "ok"
            if reached:
                did["path"] = True
                break
    name = p.block or (p.allow[0] if p.allow else None)
    if name:
        did["resolver"] = ask(name, p.gw_ip) is not None
    return did


def ruled_out(env: Env, addr: str) -> bool:
    """Is `addr` one the TV's rules refuse whatever the path: a DoH resolver's, a manual block's, the
    home LAN's? A target there says nothing about the path."""
    return any(
        env.run(["nft", "get", "element", "inet", "tvgw", name, f"{{ {addr} }}"])[0] == 0
        for name in ("doh4", "block4", "lan4")
    )


def path_due(env: Env, now: float | None = None) -> bool:
    """Whether the 10-minute check makes its connection out in this run: none for PATH_EVERY, or the
    last one did not pass and PATH_RETRY has gone by."""
    words = env.read(env.stamp).split()
    try:
        last, outcome = float(words[0]), words[1]
    except (IndexError, ValueError):
        return True
    age = (time.time() if now is None else now) - last
    return age < 0 or age >= (PATH_EVERY if outcome == PASS else PATH_RETRY)


def note_path(env: Env, v: Verdict) -> None:
    """Record a connection out that was made (not one that was skipped), for path_due."""
    outcome = next((s.outcome for s in v.stages if s.name == "path"), SKIPPED)
    if outcome != SKIPPED:
        env.write(env.stamp, f"{time.time():.0f} {outcome}\n")


def not_ready(s: Settings, env: Env) -> str | None:
    """Why no packet may be sent, or None. Without the probe's chains in the loaded firewall its packets
    would be dropped by a rule of the TV's and counted there, so nothing is sent before they are seen."""
    if s.tv_probe != "on":
        return "the probe is off (TV_PROBE=off in the settings)"
    if env.euid() != 0:
        return "the probe needs root: run it with sudo"
    try:
        probe_ip = config.probe_side(s)
    except ValueError as e:
        return str(e)
    rc, listing = env.run(["nft", "list", "chain", "inet", "tvgw", CHAIN])
    if rc != 0 or f"ip saddr != {probe_ip} " not in listing:
        return "the loaded firewall has no rules for the probe at this address yet: run sudo tvgw-apply"
    return None


class Namespace:
    """The client's namespace and its veth pair, for one run. Nothing outside the pair changes: the
    gateway end has no address, so no service binds to it and no address notifier fires; the two routes
    name only the probe's own address, so no packet of the TV's is routed differently for them."""

    def __init__(self, s: Settings, p: Plan, env: Env):
        self.s, self.p, self.env = s, p, env

    def _do(self, *cmd: str) -> None:
        rc, _ = self.env.run(list(cmd))
        if rc != 0:
            raise RuntimeError(" ".join(cmd[:4]) + " failed")

    def clear(self) -> None:
        """Remove whatever a run left, this one or one that was killed. Never raises."""
        rc, pids = self.env.run(["ip", "netns", "pids", self.env.netns])
        for pid in pids.split() if rc == 0 else []:
            with contextlib.suppress(OSError, ValueError):
                os.kill(int(pid), 9)
        self.env.run(["ip", "netns", "del", self.env.netns])
        self.env.run(["ip", "link", "del", GW_IF])

    def __enter__(self) -> Namespace:
        env, p, ns, proc = self.env, self.p, self.env.netns, "/proc/sys/net"
        self.clear()
        try:
            self._do("ip", "netns", "add", ns)
            self._do(
                "ip", "link", "add", GW_IF, "address", GW_MAC, "type", "veth",
                "peer", "name", NS_IF, "address", NS_MAC, "netns", ns,
            )  # fmt: skip
            env.write(f"{proc}/ipv6/conf/{GW_IF}/disable_ipv6", "1\n")
            env.write(f"{proc}/ipv4/conf/{GW_IF}/rp_filter", "1\n")
            # the pair's gateway end forwards exactly when the TV's port does: a port switched off keeps
            # the probe's packets back as it keeps the TV's
            tv_fwd = env.read(f"{proc}/ipv4/conf/{self.s.tv_if}/forwarding").strip()
            env.write(f"{proc}/ipv4/conf/{GW_IF}/forwarding", "1\n" if tv_fwd == "1" else "0\n")
            self._do("ip", "link", "set", GW_IF, "up")
            # the way back to the client, from GW_IP as the TV sees its answers come; in table 100 too,
            # where rule 60 sends what the gateway itself sends from GW_IP (design decision 49)
            route = ("ip", "route", "replace", f"{p.probe_ip}/32", "dev", GW_IF, "src", p.gw_ip)
            self._do(*route)
            # in table 100 whatever the uplink is now: harmless while rule 60 is absent, and there when an
            # apply this run stands across adds the rule
            self._do(*route, "table", "100")
            self._do("ip", "neigh", "replace", p.probe_ip, "lladdr", NS_MAC, "dev", GW_IF, "nud", "permanent")
            env.run(["ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1"])
            self._do("ip", "-n", ns, "link", "set", "lo", "up")
            self._do("ip", "-n", ns, "addr", "add", f"{p.probe_ip}/32", "dev", NS_IF)
            self._do("ip", "-n", ns, "link", "set", NS_IF, "up")
            self._do("ip", "-n", ns, "route", "add", f"{p.gw_ip}/32", "dev", NS_IF)
            self._do("ip", "-n", ns, "route", "add", "default", "via", p.gw_ip, "dev", NS_IF)
            self._do(
                "ip",
                "-n",
                ns,
                "neigh",
                "replace",
                p.gw_ip,
                "lladdr",
                GW_MAC,
                "dev",
                NS_IF,
                "nud",
                "permanent",
            )
        except BaseException:
            self.clear()
            raise
        return self

    def __exit__(self, *exc) -> None:
        self.clear()

    def client_argv(self, hold: float = 0.0, connect: bool = True) -> list[str]:
        argv = ["ip", "netns", "exec", self.env.netns, self.env.python, "-m", "tvgw.probe", "--client"]
        return [*argv, json.dumps(self.p.spec(connect)), *(["--hold", str(hold)] if hold > 0 else [])]

    def observe(self, connect: bool = True) -> dict | None:
        rc, out = self.env.run(self.client_argv(connect=connect), timeout=CLIENT_TIMEOUT)
        doc = _json(out.splitlines()[0]) if rc == 0 and out.strip() else None
        return doc.get("obs") if isinstance(doc, dict) and isinstance(doc.get("obs"), dict) else None


@contextlib.contextmanager
def locked(env: Env):
    """One run at a time: the namespace and the pair have one name each. Yields False when another run
    still holds them after LOCK_WAIT."""
    try:
        fd = os.open(env.lock, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        yield True  # no lock directory (not a gateway): the commands that follow say what is missing
        return
    try:
        deadline = time.monotonic() + LOCK_WAIT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    yield False
                    return
                env.sleep(0.25)
        yield True
    finally:
        os.close(fd)


def _judged(s: Settings, p: Plan, obs: dict | None, env: Env, held: Stage | None = None) -> Verdict:
    if obs is None:
        return unknown("the test client did not finish")
    for item in obs.get("path") or []:  # a target the TV's rules refuse anyway is no finding about the path
        if item.get("addr") and item.get("tls") != "ok":
            item["ruled"] = ruled_out(env, item["addr"])
    return judge(p, obs, read_port(s, p, env), read_uplink(s, env), lambda: control(p, obs), held)


def _settled(
    s: Settings,
    p: Plan,
    ns: Namespace,
    env: Env,
    first: Verdict,
    held: Stage | None = None,
    connect: bool = True,
) -> Verdict:
    """A failed verdict is taken once more after RETRY_PAUSE and stands only when it fails again: one
    lost packet, or a resolver's one slow answer, is not the TV's path."""
    if first.verdict != FAIL:
        return first
    env.sleep(RETRY_PAUSE)
    return _judged(s, p, ns.observe(connect), env, held)


def run(s: Settings, profile: Profile, env: Env | None = None, connect: bool | None = True) -> Verdict:
    """One probe: make the namespace, observe, judge (twice for a failure), remove the namespace.
    `connect` says whether this run makes the connection out; None, the 10-minute check's, makes it when
    one is due (path_due). Never raises: whatever stops it is an `unknown`, which changes nothing anywhere."""
    env = env or Env()
    t0 = time.time()
    try:
        s = live(s, env)
        why = not_ready(s, env)
        if why:
            return unknown(why, t0)
        p = plan(s, profile)
        with locked(env) as mine:
            if not mine:
                return unknown("another probe is running", t0)
            connect = path_due(env) if connect is None else connect
            with Namespace(s, p, env) as ns:
                v = _settled(s, p, ns, env, _judged(s, p, ns.observe(connect), env), connect=connect)
            note_path(env, v)
    except Exception as e:  # a probe that breaks must change nothing but its own verdict
        v = unknown(f"the probe could not run: {type(e).__name__}: {e}"[:200], t0)
    v.t, v.ms = t0, int((time.time() - t0) * 1000)
    return v


# ---- across an apply: one namespace, one connection held, a verdict on each side ------------------------


def conntrack_id(env: Env, p: Plan, held: dict) -> str | None:
    """The id of the gateway's conntrack entry for the held connection, or None (no entry, no tool)."""
    rc, out = env.run(
        ["conntrack", "-L", "-p", "tcp", "-s", p.probe_ip, "-d", str(held.get("dst")),
         "--sport", str(held.get("sport")), "--dport", "443", "-o", "id"]
    )  # fmt: skip
    ids = [w.removeprefix("id=") for w in out.split() if w.startswith("id=")] if rc == 0 else []
    return ids[0] if len(ids) == 1 else None


def uplink_address(s: Settings, env: Env) -> str | None:
    """The address the TV's connections are translated to, for held_stage: when it changes, the kernel
    itself ends every connection that carried it."""
    out_if = config.uplink_interface(
        s, lambda dev: env.read(f"/proc/sys/net/ipv4/conf/{dev}/forwarding") != ""
    )
    links = _json(env.run(["ip", "-j", "-4", "addr", "show", "dev", out_if])[1]) or []
    for link in links if isinstance(links, list) else []:
        for a in link.get("addr_info", []) if isinstance(link, dict) else []:
            if isinstance(a, dict) and a.get("scope") == "global" and a.get("local"):
                return str(a["local"])
    return None


def held_stage(before: str | None, after: str | None, peer: str | None, steady: bool = True) -> Stage:
    """The held connection after the re-apply. Its conntrack entry gone or replaced, while the far end
    never closed it, is the 2026-10-30 fault: the apply cut a live connection. Not `steady` (the uplink
    lost its carrier or changed its address meanwhile): the kernel ends those connections itself, and
    that is no apply's doing."""
    if before is None:
        return Stage("held", SKIPPED, "no connection could be held and followed")
    if after == before:
        return Stage("held", PASS)
    if not steady:
        return Stage("held", SKIPPED, "the uplink went down or changed its address meanwhile")
    if peer != "open":  # nothing to judge: the far end's own goodbye removes the entry too
        return Stage("held", SKIPPED, "the far end closed the held connection first")
    return Stage("held", FAIL, "the apply cut a live connection: its conntrack entry was destroyed")


def _line(v: Verdict) -> str:
    """A verdict as tvgw-apply reads it: `<verdict> <the deciding stage or ->` on the first line, which
    the shell reads with one `read`, then the whole of it as JSON."""
    return f"{v.verdict} {v.word or '-'}\n" + json.dumps(v.as_dict(), sort_keys=True) + "\n"


def across(s: Settings, profile: Profile, directory: str, env: Env | None = None) -> int:
    """`tvgw probe --across DIR`, what tvgw-apply brackets itself with. Writes DIR/pre, the verdict
    before; waits for DIR/go (the apply is done) or DIR/abort; then writes DIR/post, the verdict after,
    with the held connection as one more stage. Each file is written whole (renamed into place). DIR/pid,
    when the apply wrote it, is the apply's own process: once it is gone the wait ends, so an apply that
    was killed does not leave the namespace and its lock held."""
    env = env or Env()

    def publish(name: str, v: Verdict) -> None:
        tmp = os.path.join(directory, f".{name}.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(_line(v))
        os.replace(tmp, os.path.join(directory, name))

    t0 = time.time()
    proc = None
    conf = s  # the settings file's: the apply's own. Each verdict is judged by what is applied at its time
    try:
        s = live(conf, env)
        why = not_ready(s, env)
        if why:
            publish("pre", unknown(why, t0))
            return EXIT[UNKNOWN]
        p = plan(s, profile)
        with locked(env) as mine:
            if not mine:
                publish("pre", unknown("another probe is running", t0))
                return EXIT[UNKNOWN]
            with Namespace(s, p, env) as ns:
                proc = subprocess.Popen(
                    ns.client_argv(hold=HOLD_MAX + CLIENT_TIMEOUT),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, encoding="utf-8",
                )  # fmt: skip
                first = _client_line(proc, CLIENT_TIMEOUT) or {}
                obs = first.get("obs") if isinstance(first.get("obs"), dict) else None
                # taken once: a failure before the apply only means there is nothing to go back to
                pre = _judged(s, p, obs, env)
                held = first.get("held") if isinstance(first.get("held"), dict) else None
                before = conntrack_id(env, p, held) if held else None
                address = uplink_address(s, env)
                pre.t, pre.ms = t0, int((time.time() - t0) * 1000)
                publish("pre", pre)
                note_path(env, pre)
                deadline = time.monotonic() + HOLD_MAX
                applying = _pid(env.read(os.path.join(directory, "pid")))
                while not os.path.exists(os.path.join(directory, "go")):
                    gone = applying is not None and not _alive(applying)  # the apply was killed
                    if (
                        gone
                        or os.path.exists(os.path.join(directory, "abort"))
                        or time.monotonic() >= deadline
                    ):
                        return EXIT[UNKNOWN]
                    env.sleep(0.1)
                t1 = time.time()
                # the apply is done. The held connection is followed for a cut; it cannot stand for the
                # way out, since a connection made before the apply passes rules a new one would meet
                if before is not None:
                    env.sleep(HOLD_SETTLE)
                after = conntrack_id(env, p, held) if held and before is not None else None
                was, s = s, live(conf, env)
                was_p, p = p, plan(s, profile)
                if (p.probe_ip, p.gw_ip, s.tv_if) != (was_p.probe_ip, was_p.gw_ip, was.tv_if):
                    # the namespace was made for the old ones: nothing made before can judge the new
                    publish("post", unknown("the apply changed the probe's address or the TV's port"))
                    return EXIT[UNKNOWN]
                ns.s, ns.p = s, p
                assert proc.stdin is not None
                proc.stdin.write(json.dumps({"spec": p.spec()}) + "\n")
                proc.stdin.flush()
                second = _client_line(proc, CLIENT_TIMEOUT) or {}
                obs = second.get("obs") if isinstance(second.get("obs"), dict) else None
                steady = read_uplink(s, env).up and uplink_address(s, env) == address
                stage = held_stage(before, after, second.get("held_state"), steady)
                post = _settled(s, p, ns, env, _judged(s, p, obs, env, stage), stage)
                note_path(env, post)
                post.t, post.ms = t1, int((time.time() - t1) * 1000)
                publish("post", post)
                return EXIT[post.verdict]
    except Exception as e:  # as in run(): nothing but the verdict
        name = "post" if os.path.exists(os.path.join(directory, "pre")) else "pre"
        with contextlib.suppress(OSError):
            publish(name, unknown(f"the probe could not run: {type(e).__name__}: {e}"[:200]))
        return EXIT[UNKNOWN]
    finally:
        if proc is not None:
            with contextlib.suppress(OSError):
                proc.kill()
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                proc.communicate(timeout=5)


def _pid(text: str) -> int | None:
    return int(text) if text.strip().isdigit() and int(text) > 1 else None


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _client_line(proc: subprocess.Popen, timeout: float) -> dict | None:
    """The client's next line of JSON, or None when it does not come in time."""
    assert proc.stdout is not None
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    doc = _json(proc.stdout.readline()) if ready else None
    return doc if isinstance(doc, dict) else None


# ---- what a person reads ------------------------------------------------------------------------------

STAGE_PLAIN = {
    "probe": "the test itself",
    "port": "the TV's own port passes traffic on, and its route leads out (read, not crossed)",
    "lookup": "a name the TV needs is looked up and gets an address (nothing connects to it)",
    "path": "a secure connection out to a neutral server, and back, completes",
    "blocked": "a blocked name is refused by the filter",
    "dot": "an encrypted lookup (DNS over TLS) is refused",
    "quic": "QUIC is refused",
    "redirect": "a lookup aimed at a public resolver is answered by the gateway's filter",
    "held": "a connection held open across the change is still the same connection",
}
VERDICT_PLAIN = {
    PASS: "the TV would work right now, and the walls hold",
    FAIL: "from the TV's position something does not work",
    UNKNOWN: "could not tell",
}
_MARK = {PASS: "OK  ", FAIL: "FAIL", UNKNOWN: "??  ", SKIPPED: "--  "}


def lines(v: Verdict) -> list[str]:
    """The verdict in plain words: one line a stage, then the verdict."""
    out = []
    for s in v.stages:
        out.append(
            f"{_MARK[s.outcome]} {STAGE_PLAIN.get(s.name, s.name)}" + (f": {s.detail}" if s.detail else "")
        )
    out.append(f"tvgw probe: {v.verdict}: {VERDICT_PLAIN[v.verdict]}" + (f" ({v.ms} ms)" if v.ms else ""))
    return out


def main(
    s: Settings, profile: Profile, as_json: bool = False, directory: str | None = None, netns: str = ""
) -> int:
    env = Env(netns=netns or NETNS)
    if directory:
        return across(s, profile, directory, env)
    v = run(s, profile, env)
    if as_json:
        print(json.dumps(v.as_dict(), indent=1))
    else:
        print("\n".join(lines(v)))
    return EXIT[v.verdict]


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--client":
        sys.exit(client_main(sys.argv[2:]))
    sys.exit("tvgw.probe: this module is the probe's client half; run `tvgw probe`")
