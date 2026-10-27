"""tshark field extraction from the gateway's pcaps: TLS ClientHello names, plain-HTTP requests and
the SYNs the TV sends (for LAN-probe evidence).

The capture keeps only handshakes, DNS and plain HTTP (see deploy/systemd/tvgw-pcap.service), so one
tshark pass per finished hourly file is cheap. Repeated fields in one packet (pipelined HTTP
requests) are joined with `AGG`, a character that cannot occur in a URI; `parse_row` splits them
back. Wireshark's dissectors run on packets from the TV and the internet, so when we are root the
process is dropped to `nobody` first, and refused when it cannot be.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

AGG = "\x1f"  # ASCII unit separator: tshark's field aggregator
FILTER = (
    "(tls.handshake.type == 1 && tls.handshake.extensions_server_name) || http.request"
    " || (tcp.flags.syn == 1 && tcp.flags.ack == 0)"
)
FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "tcp.flags",
    "udp.srcport",
    "udp.dstport",
    "tls.handshake.extensions_server_name",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.user_agent",
)
NAME_MAX = 255  # a hostname cannot be longer; what is, is not a name
CUT_SHORT_RC = 2  # tshark exits 2 both for "cut short in the middle of a packet" (normal) and for errors
CUT_SHORT_TEXT = "cut short"  # the stderr text that tells the two apart
UNPRIVILEGED = ["setpriv", "--reuid=nobody", "--regid=nogroup", "--clear-groups", "--"]


@dataclass(frozen=True)
class TlsHello:
    t: float
    src: str
    sport: int
    dst: str
    dport: int
    sni: str


@dataclass(frozen=True)
class HttpRequest:
    t: float
    src: str
    dst: str
    method: str
    host: str
    uri: str
    user_agent: str


@dataclass(frozen=True)
class Syn:
    """A connection attempt (TCP SYN without ACK)."""

    t: float
    src: str
    sport: int
    dst: str
    dport: int


def command(pcap: str, unprivileged: bool = False) -> list[str]:
    # the TV's requests to port 80 are captured whole; without this their bodies (POSTs, uploads) would
    # be held in memory for reassembly, and the request line and headers are all that is read
    cmd = ["tshark", "-r", pcap, "-n", "-o", "http.desegment_body:FALSE"]
    cmd += ["-E", f"aggregator={AGG}", "-Y", FILTER, "-T", "fields"]
    for f in FIELDS:
        cmd += ["-e", f]
    return [*UNPRIVILEGED, *cmd] if unprivileged else cmd


def _first(v: str) -> str:
    return v.split(AGG, 1)[0] if v else ""


def _int(v: str, base: int = 10) -> int:
    try:
        return int(_first(v), base)
    except ValueError:
        return 0


def parse_row(line: str) -> list[TlsHello | HttpRequest | Syn]:
    f = line.rstrip("\n").split("\t")
    if len(f) != len(FIELDS):  # a tab inside a value shifts every later column: reject, never misfile
        return []
    t, src, sport, dst, dport, flags, usport, udport, sni, method, host, uri, ua = f
    try:
        epoch = float(_first(t))
    except ValueError:
        return []
    if sni:
        return [
            TlsHello(
                epoch,
                src,
                _int(sport) or _int(usport),
                dst,
                _int(dport) or _int(udport),
                _first(sni).lower()[:NAME_MAX],
            )
        ]
    if method:
        methods, hosts, uris = method.split(AGG), host.split(AGG), uri.split(AGG)
        n = 1
        if len(methods) > 1 and len(methods) == len(hosts) == len(uris):
            n = len(methods)  # pipelined requests, cleanly paired; otherwise keep the first only
        return [
            HttpRequest(epoch, src, dst, methods[i], hosts[i].lower()[:NAME_MAX], uris[i], _first(ua))
            for i in range(n)
        ]
    fl = _int(flags, 16)
    if fl & 0x02 and not fl & 0x10:
        return [Syn(epoch, src, _int(sport), dst, _int(dport))]
    return []


def extract(
    pcap: str, timeout: int = 600, unprivileged: bool | None = None
) -> list[TlsHello | HttpRequest | Syn]:
    """Run tshark on one pcap. Raises RuntimeError on a real failure (not on 'cut short').

    Rows are framed on newline alone: str.splitlines would also break on \\x0b, \\x0c, \\x1c-\\x1e,
    \\x85 and U+2028/9, any of which a URI or user agent from the TV may carry. `unprivileged`
    defaults to "when running as root", and root without setpriv is refused rather than run the
    dissectors as root on packets from the TV and the internet."""
    if unprivileged is None:
        unprivileged = os.geteuid() == 0
        if unprivileged and shutil.which("setpriv") is None:
            raise RuntimeError("refusing to run tshark as root: setpriv not found")
    out = subprocess.run(
        command(pcap, unprivileged),
        capture_output=True,
        encoding="utf-8",  # text=True alone would use the parent's locale
        errors="replace",
        timeout=timeout,
        cwd="/",
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/nonexistent", "LANG": "C.UTF-8"},
    )
    if out.returncode != 0 and not (out.returncode == CUT_SHORT_RC and CUT_SHORT_TEXT in out.stderr):
        # a file it could not open also exits 2: never take that for an empty capture
        raise RuntimeError(f"tshark rc={out.returncode}: {out.stderr.strip()[:200]}")
    rows: list[TlsHello | HttpRequest | Syn] = []
    for line in out.stdout.split("\n"):
        rows.extend(parse_row(line))
    return rows
