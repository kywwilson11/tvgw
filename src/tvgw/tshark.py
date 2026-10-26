"""tshark field extraction from the gateway's pcaps: TLS ClientHello names and plain-HTTP requests.

The capture keeps only handshakes, DNS and plain HTTP (see deploy/systemd/tvgw-pcap.service), so
one tshark pass per finished hourly file is cheap. tshark joins repeated fields (pipelined HTTP
requests in one segment) with commas; `parse_row` splits them back.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

FILTER = "(tls.handshake.type == 1 && tls.handshake.extensions_server_name) || http.request"
FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "tls.handshake.extensions_server_name",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.user_agent",
)
CUT_SHORT_RC = 2  # tshark's exit code for a file that ends mid-packet: normal for a finished hourly pcap


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


def command(pcap: str) -> list[str]:
    cmd = ["tshark", "-r", pcap, "-n", "-Y", FILTER, "-T", "fields"]
    for f in FIELDS:
        cmd += ["-e", f]
    return cmd


def parse_row(line: str) -> list[TlsHello | HttpRequest]:
    f = line.rstrip("\n").split("\t")
    if len(f) < len(FIELDS):
        return []
    t, src, sport, dst, dport, sni, method, host, uri, ua = f[: len(FIELDS)]
    try:
        epoch = float(t)
    except ValueError:
        return []
    if sni:
        return [TlsHello(epoch, src, int(sport or 0), dst, int(dport or 0), sni.lower())]
    if method:
        methods, hosts, uris = method.split(","), host.split(","), uri.split(",")
        n = min(len(methods), len(hosts), len(uris)) if len(methods) > 1 else 1
        if len(methods) > 1 and n != len(methods):
            n = 1  # uneven split: keep the first request rather than guess the pairing
        return [
            HttpRequest(
                epoch,
                src,
                dst,
                methods[i],
                hosts[i].lower() if n > 1 else host.lower(),
                uris[i] if n > 1 else uri,
                ua,
            )
            for i in range(n)
        ]
    return []


def extract(pcap: str, timeout: int = 600) -> list[TlsHello | HttpRequest]:
    """Run tshark on one pcap. Raises RuntimeError on a real failure (not on 'cut short')."""
    out = subprocess.run(command(pcap), capture_output=True, text=True, timeout=timeout)
    if out.returncode not in (0, CUT_SHORT_RC):
        raise RuntimeError(f"tshark rc={out.returncode}: {out.stderr.strip()[:200]}")
    rows: list[TlsHello | HttpRequest] = []
    for line in out.stdout.splitlines():
        rows.extend(parse_row(line))
    return rows
