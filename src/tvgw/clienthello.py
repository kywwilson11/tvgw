"""A TLS ClientHello read from raw bytes, and the JA4 fingerprint of a hello however it was read.

Two readers feed JA4. tshark's fields (`tshark.parse_row`) cover every hello tshark dissects, over
TCP and inside QUIC Initial packets. This module's byte parser covers the one case tshark cannot: a
hello split across TCP segments whose later segments the capture did not keep, which tshark holds
back as "TCP segment of a reassembled PDU" and never dissects. Its first segment still carries the
version, the cipher list and the extensions up to the cut, often including the server name.

The parser reads hostile input (the TV's packets, and whatever an app on it sends), so it never
raises: a short or malformed hello comes back with `complete=False` and whatever was read before the
fault, and anything that is not a ClientHello record comes back as None. It parses less than
tshark does on purpose (R&D state-of-the-art 2026-10, section 10: "parsing less").

JA4 is FoxIO's TLS client fingerprint (BSD-3-Clause; https://github.com/FoxIO-LLC/ja4, technical
details in JA4.md), checked against Wireshark's own implementation (`ssl_dissect_hnd_cli_hello` in
epan/dissectors/packet-tls-utils.c, 4.4): `a_b_c` where `a` is transport, version, SNI or not,
cipher count, extension count and the first ALPN's first and last character; `b` the first 12 hex
digits of SHA-256 over the sorted cipher list; `c` the same over the sorted extension list without
SNI and ALPN, an underscore and the signature algorithms in wire order. GREASE values (RFC 8701) are
ignored everywhere. JA4+ (JA4S, JA4H, JA4X and the rest) is under the FoxIO License and is not
implemented here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

RECORD_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000
EXT_ALPN = 0x0010
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_ECH = 0xFE0D  # encrypted_client_hello (RFC 9849)
HASH_EMPTY = "000000000000"  # JA4's stand-in for the hash of an empty list
JA4_VERSIONS = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
    0x0100: "s1",
    0xFEFF: "d1",
    0xFEFD: "d2",
    0xFEFC: "d3",
}
TRANSPORTS = {"tcp": "t", "quic": "q", "dtls": "d"}
MAX_HELLO = 1 << 17  # bytes: no real hello comes near this; a claimed length beyond it is not read


def is_grease(v: int) -> bool:
    """RFC 8701 GREASE: 0x0a0a, 0x1a1a ... 0xfafa, the values stacks insert to keep servers honest."""
    return (v & 0x0F0F) == 0x0A0A and (v & 0xFF) == (v >> 8)


@dataclass(frozen=True)
class Hello:
    """What a ClientHello says, in wire order. `complete` is False when the bytes ran out (or broke)
    before the end of the hello: the lists then hold what came before the cut, and no fingerprint is
    taken from them."""

    version: int = 0
    ciphers: tuple[int, ...] = ()
    extensions: tuple[int, ...] = ()
    sni: str = ""
    alpn: tuple[bytes, ...] = ()
    sig_algs: tuple[int, ...] = ()
    supported_versions: tuple[int, ...] = ()
    complete: bool = False

    @property
    def ech(self) -> bool:
        return EXT_ECH in self.extensions


class _Short(Exception):
    """The bytes ended (or a length lied) inside a field."""


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise _Short
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vector(self, length_bytes: int) -> bytes:
        n = int.from_bytes(self.take(length_bytes), "big")
        return self.take(n)


def is_client_hello_record(data: bytes) -> bool:
    """True when `data` begins a TLS handshake record whose first message is a ClientHello: the test
    that tells a held-back hello segment from any other segment tshark shows as raw data."""
    return len(data) >= 6 and data[0] == RECORD_HANDSHAKE and data[1] == 0x03 and data[5] == 1


def handshake_bytes(data: bytes) -> tuple[bytes, bool]:
    """The handshake bytes carried by the handshake records at the start of `data`, joined (a hello
    may be fragmented over several records), and whether the records were all there in full."""
    out = bytearray()
    pos = 0
    while pos + 5 <= len(data) and data[pos] == RECORD_HANDSHAKE and len(out) < MAX_HELLO:
        length = int.from_bytes(data[pos + 3 : pos + 5], "big")
        body = data[pos + 5 : pos + 5 + length]
        out += body
        if len(body) < length:
            return bytes(out), False
        pos += 5 + length
        if len(out) >= 4 and len(out) >= 4 + int.from_bytes(out[1:4], "big"):
            break  # the hello is whole; what follows is another message
    return bytes(out), True


def parse_record(data: bytes) -> Hello | None:
    """The ClientHello at the start of `data` (TLS records, as on the wire after the TCP header), or
    None when `data` does not begin with one."""
    if not is_client_hello_record(data):
        return None
    hs, _ = handshake_bytes(data)
    return parse_handshake(hs)


def parse_handshake(hs: bytes) -> Hello | None:
    """A ClientHello from its handshake message (type, 24-bit length, body), as tshark and QUIC CRYPTO
    frames carry it. Never raises; see `Hello.complete`."""
    if len(hs) < 4 or hs[0] != HANDSHAKE_CLIENT_HELLO:
        return None
    length = int.from_bytes(hs[1:4], "big")
    body = hs[4 : 4 + min(length, MAX_HELLO)]
    whole = len(body) == length
    fields: dict = {}
    try:
        _parse_body(_Reader(body), fields)
    except _Short:
        whole = False
    except (ValueError, UnicodeError):  # a malformed vector inside an extension
        whole = False
    return Hello(
        complete=whole and fields.get("_done", False), **{k: v for k, v in fields.items() if k[0] != "_"}
    )


def _parse_body(r: _Reader, f: dict) -> None:
    """Fill `f` field by field, so whatever was read before a cut is kept."""
    f["version"] = r.u16()
    r.take(32)  # random
    r.vector(1)  # legacy_session_id
    n = r.u16()
    ciphers: list[int] = []
    f["ciphers"] = ()
    for _ in range(n // 2):
        ciphers.append(r.u16())
        f["ciphers"] = tuple(ciphers)
    if n % 2:
        raise _Short
    r.vector(1)  # compression methods
    if r.pos == len(r.data):  # SSL 3.0 and some TLS 1.0 stacks send no extensions at all
        f["_done"] = True
        return
    ext_total = r.u16()
    end = r.pos + ext_total
    exts: list[int] = []
    while r.pos < end:
        etype = r.u16()
        exts.append(etype)
        f["extensions"] = tuple(exts)
        edata = r.vector(2)
        _extension(etype, edata, f)
    if r.pos != end:
        raise _Short
    f["_done"] = True


def _extension(etype: int, data: bytes, f: dict) -> None:
    r = _Reader(data)
    if etype == EXT_SERVER_NAME and data:
        names = _Reader(r.vector(2))
        while names.pos < len(names.data):
            kind, name = names.u8(), names.vector(2)
            if kind == 0 and not f.get("sni"):  # host_name
                f["sni"] = name.decode("ascii", "replace").lower()[:255]
    elif etype == EXT_ALPN and data:
        protos = _Reader(r.vector(2))
        out: list[bytes] = []
        while protos.pos < len(protos.data):
            out.append(protos.vector(1))
        f["alpn"] = tuple(out)
    elif etype == EXT_SIGNATURE_ALGORITHMS and data:
        raw = r.vector(2)
        f["sig_algs"] = tuple(int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw) - 1, 2))
    elif etype == EXT_SUPPORTED_VERSIONS and data:
        raw = r.vector(1)
        f["supported_versions"] = tuple(
            int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw) - 1, 2)
        )


# ---- JA4 -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Ja4Input:
    """Everything JA4 reads from a hello, whichever reader produced it."""

    transport: str  # "tcp", "quic" or "dtls"
    version: int  # the legacy client_version field
    supported_versions: Sequence[int]
    ciphers: Sequence[int]
    extensions: Sequence[int]  # wire order; GREASE included, it is dropped here
    alpn_first: bytes | None  # the first protocol name in the ALPN extension, None without one
    sig_algs: Sequence[int]  # the signature_algorithms extension (13) only, wire order


def from_hello(h: Hello, transport: str = "tcp") -> Ja4Input:
    return Ja4Input(
        transport,
        h.version,
        h.supported_versions,
        h.ciphers,
        h.extensions,
        h.alpn[0] if h.alpn else None,
        h.sig_algs,
    )


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode("ascii")).hexdigest()[:12] if s else HASH_EMPTY


def _alpn_chars(first: bytes | None) -> str:
    if not first:
        return "00"
    a, z = first[0], first[-1]
    if chr(a).isascii() and chr(a).isalnum() and chr(z).isascii() and chr(z).isalnum():
        return chr(a) + chr(z)
    return f"{a >> 4:x}{z & 0xF:x}"  # the first hex digit of the first byte, the last of the last


def _parts(i: Ja4Input) -> tuple[str, str, str]:
    versions = [v for v in i.supported_versions if not is_grease(v)]
    version = max(versions) if versions else i.version
    ciphers = sorted(c for c in i.ciphers if not is_grease(c))
    exts = [e for e in i.extensions if not is_grease(e)]
    a = (
        TRANSPORTS.get(i.transport, "t")
        + JA4_VERSIONS.get(version, "00")
        + ("d" if EXT_SERVER_NAME in exts else "i")
        + f"{min(len(ciphers), 99):02d}"
        + f"{min(len(exts), 99):02d}"
        + _alpn_chars(i.alpn_first)
    )
    b = ",".join(f"{c:04x}" for c in ciphers)
    c = ",".join(f"{e:04x}" for e in sorted(e for e in exts if e not in (EXT_SERVER_NAME, EXT_ALPN)))
    sigs = [s for s in i.sig_algs if not is_grease(s)]
    if c and sigs:
        c += "_" + ",".join(f"{s:04x}" for s in sigs)
    return a, b, c


def ja4(i: Ja4Input) -> str:
    """The JA4 fingerprint, `t13d1516h2_8daaf6152771_e5627efa2ab1` in shape."""
    a, b, c = _parts(i)
    return f"{a}_{_hash(b)}_{_hash(c)}"


def ja4_r(i: Ja4Input) -> str:
    """JA4's raw form: the lists JA4 hashes, for reading by eye and for checking a hash by hand."""
    a, b, c = _parts(i)
    return f"{a}_{b}_{c}"
