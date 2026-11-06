"""A server that completes a TLS handshake, for `tvgw probe`'s allowed half: one stdlib-only script.

    tlspeer.py CERT KEY ADDRESS [PORT]

It prints `ready` once it listens, completes a handshake with whoever connects, and then echoes whatever
arrives until the far end closes, so a connection the probe holds open across a re-apply stays open. The
certificate is the test's own, made for the run: the probe judges the path, never the certificate. It is a
separate script for the reason agent.py is one: it runs inside a namespace (`ip netns exec NS python3 -I
tlspeer.py ...`), and it imports nothing outside the standard library."""

from __future__ import annotations

import socket
import ssl
import sys
import threading


def session(conn: ssl.SSLSocket) -> None:
    with conn:
        try:
            while data := conn.recv(4096):
                conn.sendall(data)
        except OSError:
            return


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        print(__doc__, file=sys.stderr)
        return 2
    cert, key, address = argv[:3]
    port = int(argv[3]) if len(argv) == 4 else 443
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen(16)
    print("ready", flush=True)
    while True:
        raw, _peer = listener.accept()
        try:
            raw.settimeout(5)
            conn = ctx.wrap_socket(raw, server_side=True)
            conn.settimeout(None)
        except (OSError, ssl.SSLError):
            raw.close()
            continue
        threading.Thread(target=session, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
