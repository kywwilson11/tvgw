"""tshark field extraction from the gateway's pcaps: TLS ClientHellos (over TCP, and inside QUIC
Initial packets) with their JA4 fingerprint, plain-HTTP requests and the SYNs the TV sends (for
LAN-probe evidence).

The capture keeps only handshakes, DNS and plain HTTP (see deploy/systemd/tvgw-pcap.service), so one
tshark pass per finished hourly file is cheap. Repeated fields in one packet (pipelined HTTP
requests, a hello's cipher and extension lists) are joined with `AGG`, a character that cannot occur
in a URI; `parse_row` splits them back. Wireshark's dissectors run on packets from the TV and the
internet, so when we are root the process runs as `nobody` in a transient systemd unit, and is
refused when it cannot be.

A ClientHello larger than one segment (post-quantum key shares) is reassembled when every segment
was captured. When only the first segment was, tshark holds it back as part of an unfinished PDU and
never dissects it; its raw bytes (`tcp.segment_data`) are then read by `clienthello.parse_record`,
which recovers the server name when it lies in that segment. Such a hello is `partial` and has no
JA4. QUIC Initial packets are decrypted by tshark itself (their keys derive from the client's
connection ID), so a QUIC hello arrives as the same fields with UDP ports. See docs/extractor.md.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from tvgw import clienthello

AGG = "\x1f"  # ASCII unit separator: tshark's field aggregator
FILTER = (
    "tls.handshake.type == 1 || tcp.segment_data || http.request"
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
    "tls.handshake.extension.type",  # every extension type in the hello, in wire order
    # (extractor) schema 8: what JA4 reads, and the held-back first segment of a split hello. Every
    # field here exists in tshark 4.0 (Debian 12) and 4.4 (Debian 13); tshark refuses an unknown one,
    # so a field that only a newer version has (tls.handshake.ja4, 4.2+) is never asked for
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.ciphersuite",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.sig_hash_alg_len",  # one per signature list: extensions 13, 50 and 34 each carry one
    "tls.handshake.sig_hash_alg",
    "tcp.segment_data",
)
# reassembly stated, not inherited: a hello split over segments is dissected whole when they were all
# captured, whatever a preferences file on the box says
PREFS = (
    "http.desegment_body:FALSE",
    "tcp.desegment_tcp_streams:TRUE",
    "tls.desegment_ssl_records:TRUE",
)
# encrypted_client_hello. Real ECH puts the provider's public outer name in the SNI; GREASE ECH, the
# decoy a stack sends with ECH on and no config known, carries the real name. The wire cannot tell
# the two apart: only the name can (a known public name means real ECH; queries.ECH_PUBLIC_NAMES).
ECH_EXTENSION = clienthello.EXT_ECH
# extensions whose signature list tshark reports under sig_hash_alg, each with its own length field
SIG_LIST_EXTENSIONS = (0x000D, 0x0032, 0x0022)  # signature_algorithms, _cert, delegated_credentials
NAME_MAX = 255  # a hostname cannot be longer; what is, is not a name
CUT_SHORT_RC = 2  # tshark exits 2 both for "cut short in the middle of a packet" (normal) and for errors
CUT_SHORT_TEXT = "cut short"  # the stderr text that tells the two apart
REPEAT_WINDOW = 30.0  # seconds: the same connection's hello again within this is a retransmission
SANDBOX = "systemd-run"
MEMORY_MAX = "512M"
TASKS_MAX = 64  # tshark runs a handful of threads; a dissector that forks without end stops here


# the transient unit's hardening, beyond the user drop: each property removes something a dissector
# reading a pcap never needs. Every one exists in systemd 252 (Debian 12) and 257 (Debian 13).
HARDENING = (
    "PrivateNetwork=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "PrivateIPC=yes",
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "ProtectProc=invisible",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "KeyringMode=private",
    "RestrictAddressFamilies=AF_UNIX",
    "SystemCallFilter=@system-service",
    # no SystemCallErrorNumber=: a refused call kills tshark (SIGSYS), a failure ingest sees and
    # retries; EPERM instead could let it finish the file with rows silently missing
    "SystemCallArchitectures=native",
    "UMask=0077",
    "LimitCORE=0",  # a crashing dissector leaves no core holding the TV's packets
    f"TasksMax={TASKS_MAX}",
    f"MemoryMax={MEMORY_MAX}",
)


def sandbox(pcap: str, timeout: int) -> list[str]:
    """The transient unit the dissectors run in when the caller is root: nobody:nogroup (the pcaps are
    group-readable by nogroup), the `HARDENING` properties (no network, a read-only view of the
    system, no devices, no new privileges, no capabilities, the service syscall set, a memory and a
    task limit), the one pcap read-only, and a time limit. `--pipe` hands tshark's stdio to the
    caller and `--wait` makes systemd-run exit with tshark's own status, so the "cut short" exit-2
    reading is unchanged; `--collect` leaves no failed unit behind."""
    props = [*HARDENING, f"ReadOnlyPaths=-{pcap}", f"RuntimeMaxSec={timeout}"]
    return [
        SANDBOX,
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--uid=nobody",
        "--gid=nogroup",
        "--setenv=HOME=/nonexistent",
        "--setenv=LANG=C.UTF-8",
        *(x for p in props for x in ("-p", p)),
        "--",
    ]


@dataclass(frozen=True)
class TlsHello:
    """One ClientHello from a pcap. `sni` is empty for a hello without the server_name extension (an
    IP-literal connection, or a stack that leaves it out) and for a `partial` hello whose name lay in
    a segment the capture did not keep. `ja4` is empty when the hello could not be read whole."""

    t: float
    src: str
    sport: int
    dst: str
    dport: int
    sni: str
    ech: bool = False  # the hello carried the encrypted_client_hello extension
    ja4: str = ""
    transport: str = "tcp"  # "tcp", or "quic" for a hello inside a QUIC Initial packet
    partial: bool = False  # read from the first segment alone; see the module docstring


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


def command(pcap: str, unprivileged: bool = False, timeout: int = 600) -> list[str]:
    # the TV's requests to port 80 are captured whole; without the first preference their bodies
    # (POSTs, uploads) would be held in memory for reassembly, and the request line and headers are
    # all that is read. The other two keep a split hello's reassembly on (PREFS)
    cmd = ["tshark", "-r", pcap, "-n"]
    for pref in PREFS:
        cmd += ["-o", pref]
    cmd += ["-E", f"aggregator={AGG}", "-Y", FILTER, "-T", "fields"]
    for f in FIELDS:
        cmd += ["-e", f]
    return [*sandbox(pcap, timeout), *cmd] if unprivileged else cmd


def _first(v: str) -> str:
    return v.split(AGG, 1)[0] if v else ""


def _int(v: str, base: int = 10) -> int:
    try:
        return int(_first(v), base)
    except ValueError:
        return 0


def _ints(v: str) -> list[int] | None:
    """Every value of a repeated numeric field (tshark prints them in decimal or as 0x.., depending
    on the field's base and the version), or None when one of them is not a number."""
    try:
        return [int(x, 0) for x in v.split(AGG) if x]
    except ValueError:
        return None


def _sig_algs(exts: list[int], lengths: list[int], algs: list[int]) -> list[int] | None:
    """The signature_algorithms extension's list alone. tshark reports the lists of extensions 13,
    50 and 34 under one field, in wire order, each after its own byte length; JA4 wants 13's only.
    None when the lengths do not account for the values exactly (a malformed or cut extension)."""
    owners = [e for e in exts if e in SIG_LIST_EXTENSIONS]
    if len(owners) != len(lengths) or sum(n // 2 for n in lengths) != len(algs):
        return None
    pos = 0
    for ext, n in zip(owners, lengths, strict=True):
        if ext == clienthello.EXT_SIGNATURE_ALGORITHMS:
            return algs[pos : pos + n // 2]
        pos += n // 2
    return []


def fields_ja4(
    transport: str, version: str, supported: str, ciphers: str, exts: str, alpn: str, sig_len: str, sigs: str
) -> str:
    """JA4 from the dissected fields of a hello, or "" when they cannot give a faithful one: no cipher
    list (not a hello tshark read whole) or signature lists that do not add up."""
    c, e = _ints(ciphers), _ints(exts)
    lens, algs = _ints(sig_len), _ints(sigs)
    vers = _ints(supported)
    if not c or e is None or lens is None or algs is None or vers is None:
        return ""
    sig = _sig_algs(e, lens, algs)
    if sig is None:
        return ""
    first = _first(alpn)
    return clienthello.ja4(
        clienthello.Ja4Input(
            transport,
            _int(version, 0),
            vers,
            c,
            e,
            first.encode("utf-8", "replace") if first else None,
            sig,
        )
    )


def _segment_hello(
    epoch: float, src: str, sport: int, dst: str, dport: int, data: str
) -> list[TlsHello | HttpRequest | Syn]:
    """A hello tshark held back unfinished (its later segments were not captured), read from the raw
    first-segment bytes; any other held-back data is not ours to read."""
    try:
        raw = bytes.fromhex(_first(data).replace(":", ""))
    except ValueError:
        return []
    h = clienthello.parse_record(raw)
    if h is None:
        return []
    ja4 = clienthello.ja4(clienthello.from_hello(h)) if h.complete else ""
    return [TlsHello(epoch, src, sport, dst, dport, h.sni[:NAME_MAX], h.ech, ja4, "tcp", not h.complete)]


def parse_row(line: str) -> list[TlsHello | HttpRequest | Syn]:
    f = line.rstrip("\n").split("\t")
    if len(f) != len(FIELDS):  # a tab inside a value shifts every later column: reject, never misfile
        return []
    v = dict(zip(FIELDS, f, strict=True))
    try:
        epoch = float(_first(v["frame.time_epoch"]))
    except ValueError:
        return []
    src, dst = v["ip.src"], v["ip.dst"]
    tcp = bool(v["tcp.srcport"] or v["tcp.dstport"])
    sport = _int(v["tcp.srcport"]) or _int(v["udp.srcport"])
    dport = _int(v["tcp.dstport"]) or _int(v["udp.dstport"])
    sni = v["tls.handshake.extensions_server_name"]
    if sni or "1" in v["tls.handshake.type"].split(AGG):
        # TLS fields over UDP are a QUIC Initial: tshark decrypts it and dissects the hello inside
        transport = "tcp" if tcp or not (v["udp.srcport"] or v["udp.dstport"]) else "quic"
        exts = v["tls.handshake.extension.type"]
        return [
            TlsHello(
                epoch,
                src,
                sport,
                dst,
                dport,
                _first(sni).lower()[:NAME_MAX],
                any(_int(x, 0) == ECH_EXTENSION for x in exts.split(AGG) if x),  # decimal or 0x..
                fields_ja4(
                    transport,
                    v["tls.handshake.version"],
                    v["tls.handshake.extensions.supported_version"],
                    v["tls.handshake.ciphersuite"],
                    exts,
                    v["tls.handshake.extensions_alpn_str"],
                    v["tls.handshake.sig_hash_alg_len"],
                    v["tls.handshake.sig_hash_alg"],
                ),
                transport,
            )
        ]
    method, host, uri, ua = (
        v["http.request.method"],
        v["http.host"],
        v["http.request.uri"],
        v["http.user_agent"],
    )
    if method:
        methods, hosts, uris = method.split(AGG), host.split(AGG), uri.split(AGG)
        n = 1
        if len(methods) > 1 and len(methods) == len(hosts) == len(uris):
            n = len(methods)  # pipelined requests, cleanly paired; otherwise keep the first only
        return [
            HttpRequest(epoch, src, dst, methods[i], hosts[i].lower()[:NAME_MAX], uris[i], _first(ua))
            for i in range(n)
        ]
    if v["tcp.segment_data"]:
        return _segment_hello(epoch, src, sport, dst, dport, v["tcp.segment_data"])
    fl = _int(v["tcp.flags"], 16)
    if fl & 0x02 and not fl & 0x10:
        return [Syn(epoch, src, _int(v["tcp.srcport"]), dst, _int(v["tcp.dstport"]))]
    return []


def dedupe(rows: list[TlsHello | HttpRequest | Syn]) -> list[TlsHello | HttpRequest | Syn]:
    """One hello per connection attempt. A retransmitted ClientHello (TCP) or a repeated Initial
    (QUIC) is dissected again, and a split hello's first segment can show as held-back data before
    its reassembled whole: within REPEAT_WINDOW on the same transport and four-tuple the first hello
    is kept, except that a whole hello replaces a partial one. Other rows pass unchanged."""
    out: list[TlsHello | HttpRequest | Syn] = []
    last: dict[tuple, int] = {}
    for r in rows:
        if not isinstance(r, TlsHello):
            out.append(r)
            continue
        key = (r.transport, r.src, r.sport, r.dst, r.dport)
        i = last.get(key)
        if i is not None and 0 <= r.t - out[i].t <= REPEAT_WINDOW:
            kept = out[i]
            if isinstance(kept, TlsHello) and kept.partial and not r.partial:
                out[i] = r
            continue
        last[key] = len(out)
        out.append(r)
    return out


def extract(
    pcap: str, timeout: int = 600, unprivileged: bool | None = None
) -> list[TlsHello | HttpRequest | Syn]:
    """Run tshark on one pcap. Raises RuntimeError on a real failure (not on 'cut short').

    Rows are framed on newline alone: str.splitlines would also break on \\x0b, \\x0c, \\x1c-\\x1e,
    \\x85 and U+2028/9, any of which a URI or user agent from the TV may carry. `unprivileged`
    defaults to "when running as root", and root without systemd-run is refused rather than run the
    dissectors as root on packets from the TV and the internet."""
    if unprivileged is None:
        unprivileged = os.geteuid() == 0
        if unprivileged and shutil.which(SANDBOX) is None:
            raise RuntimeError(f"refusing to run tshark as root: {SANDBOX} not found")
    out = subprocess.run(
        command(pcap, unprivileged, timeout),
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
    return dedupe(rows)
