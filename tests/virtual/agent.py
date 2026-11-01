"""The probes and the stand-in services of the virtual gateway: one stdlib-only script, run in a namespace.

    agent.py serve [--bind ADDR,...] [--dns ANSWER [--dns-port N]] [--tcp PORTS] [--udp PORTS] [--gre]
    agent.py probe KIND TARGET [PORT] [--src ADDR] [--sport N] [--iface IF] [--timeout S]

It is a separate script, not code the test process calls, because each half has to run inside a network
namespace (`ip netns exec NS python3 -I agent.py ...`) and a process enters a namespace whole. It
imports nothing outside the standard library, so the root interpreter that runs it needs no tvgw.

`serve` prints `ready` once every socket is bound and then answers until it is killed:
- TCP: sends `peer=<the address it saw>` and a newline, then echoes whatever arrives. The peer address
  is how a probe knows which uplink its connection left by (masquerade rewrites the source to the
  uplink's address) or that it was not NATed at all.
- UDP: answers each datagram with `peer=<address> <the datagram>`.
- DNS (`--dns ANSWER`, UDP and TCP port 53 or `--dns-port`): answers every A query with ANSWER, so the
  probe can tell the gateway's resolver from one on the internet by the address it gets back.
- GRE (`--gre`): echoes every GRE payload back to its sender, so a tunnel that got through is seen.

`probe` prints one verdict line and exits 0 (exit 2 is a usage error):
- `pass:<peer>` (TCP, UDP), `pass` (ping, GRE), `answer:<address>` (DNS), `sent` (IPv6, which only the
  gateway's counter can judge);
- `reject`: the gateway refused it at once (a TCP reset, or an ICMP port, host or admin unreachable);
- `drop`: nothing came back within the timeout;
- `error:<errno name>` for anything else, which no matrix row expects.
`probe hold TARGET PORT` keeps a TCP connection open: it prints `connected:<peer>`, then sends each line
it reads on stdin and prints `echo:<line>` for the answer, until stdin closes."""

from __future__ import annotations

import argparse
import errno
import os
import random
import select
import socket
import struct
import sys
import threading
import time

REJECT_ERRNOS = {errno.ECONNREFUSED, errno.ECONNRESET, errno.EHOSTUNREACH, errno.ENETUNREACH}
DNS_PORT = 53
GRE = 47
TIMEOUT = 1.5  # a veth pair answers in well under a millisecond; a drop is what is still silent then


# --- DNS, the few bytes the probe and the stand-in resolvers need (RFC 1035 section 4) ---------------


def dns_query(qid: int, name: str) -> bytes:
    """An A query with recursion desired."""
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split("."))
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)


def _skip_name(msg: bytes, i: int) -> int:
    """The offset just after the (possibly compressed) name at i."""
    while True:
        n = msg[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


def dns_answer(query: bytes, address: str) -> bytes:
    """The reply to `query` that names `address` for its question, whatever the question asked."""
    qid, flags = struct.unpack(">HH", query[:4])
    end = _skip_name(query, 12) + 4
    header = struct.pack(">HHHHHH", qid, 0x8000 | (flags & 0x0100) | 0x0080, 1, 1, 0, 0)
    record = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(address)
    return header + query[12:end] + record


def dns_parse(reply: bytes, qid: int) -> str | None:
    """The first A address in `reply`, or None when it is not a reply to `qid` or holds no A record."""
    if len(reply) < 12:
        return None
    rid, flags, qd, an = struct.unpack(">HHHH", reply[:8])
    if rid != qid or not flags & 0x8000:
        return None
    i = 12
    try:
        for _ in range(qd):
            i = _skip_name(reply, i) + 4
        for _ in range(an):
            i = _skip_name(reply, i)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", reply[i : i + 10])
            i += 10
            if rtype == 1 and rdlen == 4 and len(reply) >= i + 4:
                return socket.inet_ntoa(reply[i : i + 4])
            i += rdlen
    except (IndexError, struct.error):
        return None
    return None


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionResetError(errno.ECONNRESET, "closed early")
        data += chunk
    return data


# --- serve -------------------------------------------------------------------------------------------


def _tcp_session(conn: socket.socket, peer: str, dns: str | None) -> None:
    with conn:
        try:
            if dns is not None:  # DNS over TCP: a two-byte length before each message
                while True:
                    (n,) = struct.unpack(">H", _recv_exact(conn, 2))
                    reply = dns_answer(_recv_exact(conn, n), dns)
                    conn.sendall(struct.pack(">H", len(reply)) + reply)
            conn.sendall(f"peer={peer}\n".encode("ascii"))
            while data := conn.recv(4096):
                conn.sendall(data)
        except OSError:
            return


def _tcp_server(sock: socket.socket, dns: str | None) -> None:
    while True:
        conn, (peer, _port) = sock.accept()
        threading.Thread(target=_tcp_session, args=(conn, peer, dns), daemon=True).start()


def _udp_server(sock: socket.socket, dns: str | None) -> None:
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            reply = dns_answer(data, dns) if dns is not None else f"peer={addr[0]} ".encode("ascii") + data
        except (IndexError, struct.error):
            continue
        sock.sendto(reply, addr)


def _gre_server(sock: socket.socket) -> None:
    while True:
        packet, (src, _) = sock.recvfrom(65535)
        ihl = (packet[0] & 0x0F) * 4  # a raw IPv4 socket hands over the IP header too
        sock.sendto(packet[ihl:], (src, 0))


def serve(
    bind: list[str], dns: str | None, tcp: list[int], udp: list[int], gre: bool, dns_port: int = DNS_PORT
) -> None:
    """Bind everything first, then say ready: a probe may start the moment it reads the line.

    Each address gets sockets of its own. A UDP or raw socket bound to the wildcard answers from
    whatever source the kernel picks for the route back (the uplink's address, not the one the probe
    wrote to), and the probe's connected socket would then never accept the answer."""
    workers: list[tuple] = []

    def listener(address: str, kind: int, port: int) -> socket.socket:
        s = socket.socket(socket.AF_INET, kind)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # (guard) a canary on the wildcard and another on one address, same port: Linux refuses the
        # second bind beside a listening TCP socket unless both set SO_REUSEPORT
        if hasattr(socket, "SO_REUSEPORT"):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind((address, port))
        if kind == socket.SOCK_STREAM:
            s.listen(64)
        return s

    for address in bind:
        for port in tcp:
            workers.append((_tcp_server, listener(address, socket.SOCK_STREAM, port), None))
        for port in udp:
            workers.append((_udp_server, listener(address, socket.SOCK_DGRAM, port), None))
        if dns is not None:
            workers.append((_tcp_server, listener(address, socket.SOCK_STREAM, dns_port), dns))
            workers.append((_udp_server, listener(address, socket.SOCK_DGRAM, dns_port), dns))
        if gre:
            raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, GRE)
            raw.bind((address, 0))  # receives only what is sent to this address, and answers from it
            workers.append((_gre_server, raw))
    for target, *args in workers:
        threading.Thread(target=target, args=args, daemon=True).start()
    print("ready", flush=True)
    while True:
        time.sleep(3600)


# --- probe -------------------------------------------------------------------------------------------


def _failure(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return "drop"
    if isinstance(exc, OSError) and exc.errno in REJECT_ERRNOS:
        return "reject"
    code = exc.errno if isinstance(exc, OSError) else None
    return f"error:{errno.errorcode.get(code, type(exc).__name__) if code else type(exc).__name__}"


def _peer(line: bytes) -> str:
    text = line.decode("ascii", "replace").strip()
    return text.removeprefix("peer=").split(" ", 1)[0] if text.startswith("peer=") else "?"


def _stream(target: str, port: int, src: str | None, timeout: float) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if src:
        s.bind((src, 0))
    s.connect((target, port))
    return s


def probe_tcp(target: str, port: int, src: str | None = None, timeout: float = TIMEOUT) -> str:
    try:
        with _stream(target, port, src, timeout) as s:
            return f"pass:{_peer(s.makefile('rb').readline())}"
    except (OSError, TimeoutError) as exc:
        return _failure(exc)


def probe_udp(
    target: str, port: int, src: str | None = None, timeout: float = TIMEOUT, sport: int = 0
) -> str:
    """`sport` (guard): a fixed source port, for DHCP's 68 -> 67, which the firewall allows from 68 only."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            if src or sport:
                s.bind((src or "", sport))
            s.connect((target, port))
            s.send(b"tvgw-probe")
            return f"pass:{_peer(s.recv(4096))}"
    except (OSError, TimeoutError) as exc:
        return _failure(exc)


def probe_dns(target: str, port: int, tcp: bool, timeout: float = TIMEOUT) -> str:
    qid = random.randrange(1, 0xFFFF)
    query = dns_query(qid, "probe.tvgw.example")
    try:
        if tcp:
            with _stream(target, port, None, timeout) as s:
                s.sendall(struct.pack(">H", len(query)) + query)
                (n,) = struct.unpack(">H", _recv_exact(s, 2))
                reply = _recv_exact(s, n)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((target, port))  # a reply from any other address is not accepted
                s.send(query)
                reply = s.recv(4096)
    except (OSError, TimeoutError) as exc:
        return _failure(exc)
    address = dns_parse(reply, qid)
    return f"answer:{address}" if address else "error:garbled"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _raw_wait(sock: socket.socket, deadline: float, match) -> bool:
    while (left := deadline - time.monotonic()) > 0:
        ready, _, _ = select.select([sock], [], [], left)
        if not ready:
            return False
        packet, (src, _) = sock.recvfrom(65535)
        ihl = (packet[0] & 0x0F) * 4
        if match(src, packet[ihl:]):
            return True
    return False


def probe_ping(target: str, size: int, timeout: float = TIMEOUT) -> str:
    """One echo request with `size` bytes of payload: the IP packet is size + 28 bytes long."""
    ident, payload = os.getpid() & 0xFFFF, bytes(size)
    head = struct.pack(">BBHHH", 8, 0, 0, ident, 1)
    packet = struct.pack(">BBHHH", 8, 0, _checksum(head + payload), ident, 1) + payload
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
            s.sendto(packet, (target, 0))
            # the gateway rewrites the echo identifier on the way out and back; what returns has ours
            seen = _raw_wait(
                s,
                time.monotonic() + timeout,
                lambda src, icmp: src == target and icmp[:1] == b"\x00" and icmp[4:6] == packet[4:6],
            )
    except OSError as exc:
        return _failure(exc)
    return "pass" if seen else "drop"


def probe_gre(target: str, timeout: float = TIMEOUT) -> str:
    payload = b"\x00\x00\x08\x00tvgw-probe"  # a GRE header (no flags, IPv4 inside) and a marker
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, GRE) as s:
            s.sendto(payload, (target, 0))
            seen = _raw_wait(s, time.monotonic() + timeout, lambda src, gre: src == target and gre == payload)
    except OSError as exc:
        return _failure(exc)
    return "pass" if seen else "drop"


def probe_udp6(target: str, port: int, iface: str) -> str:
    """A datagram to an IPv6 (link-local or multicast) address on `iface`; only the gateway's IPv6 guard
    counter can say what became of it."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.sendto(b"tvgw-probe", (target, port, 0, socket.if_nametoindex(iface)))
    except OSError as exc:
        return _failure(exc)
    return "sent"


def hold(target: str, port: int, timeout: float = TIMEOUT) -> int:
    """A connection kept open across a re-apply: the caller writes lines, each comes back echoed."""
    try:
        s = _stream(target, port, None, timeout)
        reader = s.makefile("rb")
        print(f"connected:{_peer(reader.readline())}", flush=True)
        for line in sys.stdin:
            s.sendall(line.encode("utf-8"))
            print(f"echo:{reader.readline().decode('utf-8').rstrip()}", flush=True)
    except (OSError, TimeoutError) as exc:
        print(_failure(exc), flush=True)
    return 0


def probe(
    kind: str,
    target: str,
    port: int | None,
    src: str | None,
    iface: str | None,
    timeout: float,
    sport: int = 0,
) -> str:
    if kind == "tcp":
        return probe_tcp(target, port or 0, src, timeout)
    if kind == "udp":
        return probe_udp(target, port or 0, src, timeout, sport)
    if kind in ("dns-udp", "dns-tcp"):
        return probe_dns(target, port or DNS_PORT, kind == "dns-tcp", timeout)
    if kind == "ping":
        return probe_ping(target, port if port is not None else 56, timeout)
    if kind == "gre":
        return probe_gre(target, timeout)
    if kind == "udp6":
        return probe_udp6(target, port or 9, iface or "eth0")
    raise ValueError(f"unknown probe {kind!r}")


def _ports(text: str) -> list[int]:
    return [int(p) for p in text.split(",") if p]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agent.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve")
    sv.add_argument("--bind", type=lambda t: t.split(","), default=["0.0.0.0"])
    sv.add_argument("--dns")
    sv.add_argument("--dns-port", type=int, default=DNS_PORT)
    sv.add_argument("--tcp", type=_ports, default=[])
    sv.add_argument("--udp", type=_ports, default=[])
    sv.add_argument("--gre", action="store_true")
    pr = sub.add_parser("probe")
    pr.add_argument("kind")
    pr.add_argument("target")
    pr.add_argument("port", nargs="?", type=int)
    pr.add_argument("--src")
    pr.add_argument("--sport", type=int, default=0)
    pr.add_argument("--iface")
    pr.add_argument("--timeout", type=float, default=TIMEOUT)
    a = ap.parse_args(argv)
    if a.cmd == "serve":
        serve(a.bind, a.dns, a.tcp, a.udp, a.gre, a.dns_port)
        return 0
    if a.kind == "hold":
        return hold(a.target, a.port or 0, a.timeout)
    try:
        print(probe(a.kind, a.target, a.port, a.src, a.iface, a.timeout, a.sport), flush=True)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
