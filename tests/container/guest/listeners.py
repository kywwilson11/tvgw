"""Every listening socket the gateway ever has, sampled from /proc every 0.1 seconds (stdlib only).

Run inside the container as `python3 -I listeners.py <file>` (ctr.Gateway.watch_listeners starts it as a
transient unit before AdGuard Home is installed). Each socket seen is one `proto address port` line in
<file>, rewritten whole whenever a new one appears, so a listener that lived for a fraction of a second
(AdGuard's first-run wizard, its page while it rebinds) is still there for the tests to read. A TCP socket
counts when it is listening; a UDP socket when it is bound and not connected, which is how a server's
socket looks. /proc/net is the container's own network namespace, so the TV's namespace is not in it."""

from __future__ import annotations

import ipaddress
import os
import sys
import time

TABLES = (("tcp", "tcp", False), ("tcp6", "tcp", True), ("udp", "udp", False), ("udp6", "udp", True))
TCP_LISTEN = "0A"
UDP_UNCONNECTED = "07"


def address(hex_addr: str, v6: bool) -> str:
    """/proc/net's address, stored as the kernel's 32-bit words in host (little-endian) order."""
    raw = bytes.fromhex(hex_addr)
    words = b"".join(raw[i : i + 4][::-1] for i in range(0, len(raw), 4))
    return str(ipaddress.IPv6Address(words) if v6 else ipaddress.IPv4Address(words))


def parse(text: str, proto: str, v6: bool) -> set[tuple[str, str, int]]:
    """The listening sockets of one /proc/net table as (proto, address, port)."""
    out = set()
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        local, remote, state = fields[1], fields[2], fields[3]
        if proto == "tcp" and state != TCP_LISTEN:
            continue
        if proto == "udp" and (state != UDP_UNCONNECTED or int(remote.rpartition(":")[2], 16) != 0):
            continue
        host, _, port = local.rpartition(":")
        try:
            out.add((proto, address(host, v6), int(port, 16)))
        except ValueError:
            continue
    return out


def read_file(path: str) -> str:
    with open(path, encoding="ascii") as f:
        return f.read()


def sample(read=read_file) -> set[tuple[str, str, int]]:
    seen = set()
    for name, proto, v6 in TABLES:
        try:
            seen |= parse(read(f"/proc/net/{name}"), proto, v6)
        except OSError:  # a kernel without IPv6 has no tcp6
            continue
    return seen


def lines(seen: set[tuple[str, str, int]]) -> str:
    return "".join(f"{p} {a} {n}\n" for p, a, n in sorted(seen, key=lambda x: (x[2], x[0], x[1])))


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: listeners.py <file>", file=sys.stderr)
        return 2
    path = argv[1]
    seen: set[tuple[str, str, int]] = set()
    while True:
        now = seen | sample()
        if now != seen or not os.path.exists(path):
            seen = now
            with open(path + ".tmp", "w", encoding="ascii") as f:
                f.write(lines(seen))
            os.replace(path + ".tmp", path)
        time.sleep(0.1)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
