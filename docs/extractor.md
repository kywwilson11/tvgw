# The TLS and QUIC extractor

This page owns what the ingest reads out of each pcap about TLS: the ClientHello fields it keeps, how a hello split over segments and a hello inside a QUIC Initial are read, the JA4 fingerprint and what it is for, the ECH canary, the sandbox the dissectors run in, the limits, and how to check a new extractor on the Pi. It is for developers changing `src/tvgw/tshark.py` or `src/tvgw/clienthello.py`, and for the owner validating a deploy. The columns themselves are in [the data model](data-model.md#tls); the capture that produces the pcaps is in [privacy and retention](privacy-and-retention.md#what-the-capture-keeps).

It implements, from the [R&D survey of 2026-10](research/state-of-the-art-2026-10.md): in section 1.2, JA4 computed by our extractor, QUIC Initial server-name extraction, and the ECH canary with its outer name (all ADOPT NOW), and the split-ClientHello finding of section 1.1; in section 10, the `systemd-run` sandbox and "parsing less"; in section 11, golden corpora keyed by tool version and property tests. The decisions are 23 to 27 in [the design decisions](design-decisions.md).

## What is extracted

One tshark pass per finished hourly pcap returns three kinds of rows: TLS ClientHellos, plain-HTTP requests and the TV's SYNs. This page is about the first. For each hello from the TV, ingest keeps:

| Field | What it holds | Where it is stored |
|---|---|---|
| Time, destination, ports | The frame that completed the hello, its destination and the TCP or UDP ports | `tls` or `tls_noname` |
| Server name | The first `host_name` in the `server_name` extension, lowercased, at most 255 characters; empty when the hello has none | `tls.sni` |
| ECH | Whether the hello carried the `encrypted_client_hello` extension (`0xfe0d`) | `tls.ech` |
| JA4 | The hello's [JA4](#ja4) fingerprint; empty when the hello could not be read whole | `tls.ja4`, `tls_noname.ja4` |
| Transport | `tcp`, or `quic` for a hello inside a QUIC Initial packet | `transport` |
| Partial | `1` when the hello was read from its first TCP segment alone (below) | `partial` |

A hello with a server name goes to `tls`, as before. A hello without one goes to `tls_noname`: every reader of `tls` takes `sni` for the connection's name, and these have none ([design decision 24](design-decisions.md#24-extractor-a-hello-without-a-name-gets-its-own-table)). `pcaps_done.tls_rows` still counts the named hellos only, so counts from before and after this change compare.

## How a hello is read

**One pass.** `tshark.command` runs tshark once per file with a display filter that keeps every ClientHello (`tls.handshake.type == 1`, with or without a server name), every frame holding data tshark is waiting to reassemble (`tcp.segment_data`), plain-HTTP requests and SYNs. It names its reassembly preferences on the command line (`PREFS`), so a preferences file on the box cannot turn reassembly off.

**A hello over several segments.** A ClientHello with a post-quantum key share is about 1.8 kB, more than one TCP segment, and Chromium-family stacks shuffle their extensions so the server name can land in the second segment ([tldr.fail](https://tldr.fail/)). When every segment is in the pcap, tshark reassembles the hello and dissects it whole. When only the first is, tshark holds it back as "TCP segment of a reassembled PDU" and never dissects it, and before this change that hello was lost even when its name was in the first segment. Now the held-back bytes come out as `tcp.segment_data`, and `clienthello.parse_record` reads them: the version, the ciphers, and the extensions up to the cut. When the `server_name` extension lies wholly inside the kept bytes, the hello is stored under that name with `partial = 1` and no JA4; when it does not, the hello goes to `tls_noname` with `partial = 1`. The parser never raises: a cut or malformed hello comes back incomplete with whatever was read before the fault ([design decision 23](design-decisions.md#23-extractor-parse-the-held-back-first-segment-of-a-split-hello)).

**QUIC Initial packets.** A QUIC Initial is encrypted, but with keys anyone can derive from the client's destination connection ID and a published salt ([RFC 9001 section 5.2](https://www.rfc-editor.org/rfc/rfc9001#section-5.2)). tshark decrypts it itself and dissects the ClientHello inside its CRYPTO frames with the same TLS fields, so a QUIC hello arrives as an ordinary row with UDP ports. The extractor marks it `transport = 'quic'`, and its JA4 begins with `q`. The firewall rejects QUIC, so each of these names an attempt the TV made over HTTP/3 before it fell back to TCP. No Python decryption was added: tshark already does it, in the same sandbox, and it keeps the one-pass design.

**Repeats.** A retransmitted ClientHello and a repeated QUIC Initial are dissected again, and a split hello's first segment can show as held-back data before its reassembled whole. `tshark.dedupe` keeps one hello per transport and four-tuple within `REPEAT_WINDOW = 30` seconds: the first one, except that a whole hello replaces a partial one. A new connection that reuses the same ports after the window counts again. `tvgw.tshark.extract(..., keep_repeats=True)` skips this, for comparisons with the old extractor.

## JA4

JA4 is FoxIO's TLS client fingerprint, BSD-3-Clause ([FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)). It has three parts, `a_b_c`, for example `t13d1516h2_8daaf6152771_e5627efa2ab1`:

- `a`: transport (`t` TCP, `q` QUIC), TLS version (the highest in `supported_versions`, else the hello's own), `d` with a server name or `i` without, the cipher count and the extension count (two digits each, at most 99), and the first and last character of the first ALPN value (`00` without ALPN; hex digits when either end is not a letter or digit).
- `b`: the first 12 hex digits of SHA-256 over the sorted cipher list.
- `c`: the same over the sorted extension list without `server_name` and ALPN, then an underscore and the signature algorithms in wire order.

GREASE values ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701)) are ignored everywhere. Because both lists are sorted, JA4 does not change when Chromium permutes its extensions, which is why JA3 is not used.

**How it is computed.** `clienthello.ja4` computes it, from tshark's fields for a hello tshark dissected and from the bytes for one the parser read. The fields it reads (cipher list, extension types, `supported_versions`, ALPN, the signature lists) exist in tshark 4.0, Debian 12's version, and 4.4, Debian 13's. tshark's own `tls.handshake.ja4` field exists only from 4.2, and tshark refuses to start when asked for a field it does not have, so the extractor never asks for it and the same code runs on both releases ([design decision 25](design-decisions.md#25-extractor-ja4-is-computed-from-the-fields-not-taken-from-tshark)). tshark prints the lists of `signature_algorithms`, `signature_algorithms_cert` and `delegated_credentials` under one field, each after its own length; the extractor takes `signature_algorithms`' list by walking the lengths in extension order, and stores no fingerprint when they do not add up. The computation follows Wireshark's own (`ssl_dissect_hnd_cli_hello` in `packet-tls-utils.c`), and the [golden corpus](../tests/corpora/README.md) pins it to the spec's worked example and, on the Pi, to tshark.

**Naming without a server name.** A fingerprint is a TLS stack: one browser engine, one app's bundled BoringSSL, one platform library. A hello without a name says nothing about where it went, but its JA4 says which stack sent it. `queries.tls_noname` groups the TV's nameless hellos by address, port, transport and JA4, and lists under `stack_names` the names the same fingerprint carried in the window and the week before. A nameless hello to a hardcoded address whose JA4 also talks to an app's CDN is that app's stack, connecting where no lookup named. The brief's JSON (`tvgw brief --json`) carries the list as `tls_noname`; no text section shows it yet.

**What JA4 is not.** It names a stack, not an app: apps that share the platform's TLS library share a fingerprint, and a firmware update that changes the library changes every fingerprint at once. It is not a block criterion and nothing blocks on it. JA4+ (JA4S, JA4H, JA4X and the rest) is under the FoxIO License and is not implemented ([state of the art, section 1.1](research/state-of-the-art-2026-10.md#11-findings)).

## The ECH canary

The `encrypted_client_hello` extension is recorded on every hello as `tls.ech`. Under ECH the server name on the wire is the outer name, the provider's public name; the real name is encrypted, and the store's `sni` is the outer name because it is the only one there is. Chromium also sends the extension as GREASE, with the real name outside, in every hello that has no ECH config, and the wire cannot tell the two apart. `queries.ech_seen` decides by the name: an outer name in `ECH_PUBLIC_NAMES` (`cloudflare-ech.com`, 99.99% of deployments in 2026) is real ECH whatever the TV looked up; any other name the TV looked up in the window or the day before is GREASE; a name it never looked up is counted as real. The red line fires on real ECH ([design decision 26](design-decisions.md#26-extractor-a-known-ech-public-name-is-real-ech)).

## The sandbox

When ingest runs as root, tshark runs in a transient unit made by `systemd-run --wait --pipe --collect`, as `nobody:nogroup`, with the properties in `tshark.HARDENING`: no network (`PrivateNetwork`), a read-only system (`ProtectSystem=strict`), no home, private `/tmp`, devices and IPC, no new privileges and no capabilities, kernel tunables, modules, logs, clock, hostname and control groups protected, other processes invisible, no namespaces, realtime or set-id files, the `@system-service` system calls on the native architecture only, a private keyring, `umask 077`, no core dumps, `TasksMax=64` and `MemoryMax=512M`. The one pcap is the only file it is given (`ReadOnlyPaths=`), and `RuntimeMaxSec=` bounds a dissector loop. A refused system call kills tshark, which ingest sees and retries; `SystemCallErrorNumber=` is deliberately not set, because an `EPERM` could let tshark finish the file with rows missing. Every property exists in systemd 252 (Debian 12) and 257 (Debian 13).

As root without `systemd-run`, ingest refuses to run tshark at all; as an ordinary user it runs tshark directly. There is no weaker fallback: the dissectors parse packets from the TV and the internet ([state of the art, section 10](research/state-of-the-art-2026-10.md#10-security-and-sandboxing), [design decision 27](design-decisions.md#27-extractor-the-tshark-sandbox-has-no-weaker-fallback)).

## Limits

- **A name in a lost segment stays lost.** The parser reads only the bytes captured. When the BPF filter keeps the first segment of a split hello and the name is in the second, the hello is a partial row in `tls_noname`. The position-based capture of the R&D survey (section 1.2) keeps whole handshakes; until then the partial count shows how often this happens.
- **No JA4 for a partial hello.** The cipher and extension lists are incomplete, so any fingerprint would be wrong.
- **ALPN names that are not ASCII.** The fields path reads the ALPN value as tshark prints it, decoded as UTF-8. A protocol name with bytes outside ASCII may give different ALPN characters than tshark's native JA4. No stack seen on the gateway sends one.
- **A hello split over QUIC packets that were not all captured.** tshark reassembles CRYPTO frames across Initials; the capture keeps every QUIC long-header packet, so this needs a capture fault. Such a hello is not recovered.
- **QUIC versions.** tshark decrypts the Initials of the QUIC versions it knows (v1 in every supported release); a version it does not know yields no hello. The corpus covers v1 only.
- **Older rows.** Rows from before schema 8 have NULL `ja4`, `transport` and `partial`. Hellos without a name from before schema 8 were never stored.

## Validating on the Pi

After a deploy (CI's hardware job runs `deploy/sync-install.sh`), check each of these. Commands run on the Pi.

1. **The store is at schema 8.** The hardware suite's schema test does this; by hand:

   ```sh
   tvgw sql "SELECT value FROM meta WHERE key = 'schema'"
   tvgw sql "SELECT COUNT(*) FROM tls_noname"
   ```

2. **The sandbox runs tshark.** The next hourly ingest must not warn `pcap(s) could not be read`. To try one file at once, as root:

   ```sh
   f=$(ls /var/lib/tvgw/pcap/tv-*.pcap | head -1)
   sudo /opt/tvgw-venv/bin/python -c "import sys; from tvgw import tshark; print(len(tshark.extract(sys.argv[1])))" "$f"
   ```

   A `tshark rc=` error naming a signal or `Bad system call` means a hardening property blocks something tshark needs; the property list is `HARDENING` in `src/tvgw/tshark.py`.

3. **The corpus agrees with the installed tshark.** As an ordinary user, in a copy of the deployed tree (it belongs to root):

   ```sh
   cp -a /opt/tvgw/src ~/tvgw-corpus && cd ~/tvgw-corpus
   PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /opt/tvgw-venv/bin/python -m pytest -q tests/unit/test_corpora.py -p no:cacheprovider
   PYTHONPATH=src /opt/tvgw-venv/bin/python tests/corpora/record.py
   ```

   The tshark tests must run and pass, not skip. Copy the `tests/corpora/rows/tshark-<version>/` that `record.py` writes into a development checkout and commit it.

4. **A day of pcaps, before and after.** The pcaps of the last `PCAP_DAYS` days are kept after they are read, and `pcaps_done.tls_rows` holds what the old extractor stored from each. This reads one day's files again with the new extractor, without writing to the store, and prints both:

   ```sh
   sudo /opt/tvgw-venv/bin/python - 20261031 <<'EOF'
   import glob, os, sqlite3, sys
   from tvgw import config, tshark
   s = config.load()
   conn = sqlite3.connect(f"file:{s.db_path}?mode=ro", uri=True)
   old = dict(conn.execute("SELECT name, tls_rows FROM pcaps_done WHERE error IS NULL"))
   print("file old named nameless partial quic ja4 ech raw_named")
   for path in sorted(glob.glob(os.path.join(s.pcap_dir, f"tv-{sys.argv[1]}T*.pcap"))):
       name = os.path.basename(path)
       if name in old:
           new = tshark.summary(tshark.extract(path), s.tv_ip)
           raw = tshark.summary(tshark.extract(path, keep_repeats=True), s.tv_ip)
           print(name, old[name], *new.values(), raw["named"])
   EOF
   ```

   Read it this way. `raw_named` must be at least `old` in every file: every hello the old extractor stored is still found. `named` may be lower than `old` by the repeats now dropped, and higher by partial hellos whose name was recovered. `partial` is the number of split hellos the capture cut; `nameless` minus `partial` is hellos sent without a name; `quic` is HTTP/3 attempts. A file where `raw_named` is below `old` is a regression: keep the file and open an issue.
