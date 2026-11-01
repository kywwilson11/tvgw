# Golden corpus for the extractor

This folder holds small pcaps of TLS ClientHellos, the tshark rows each one should produce, and the hellos the extractor must return for it. It is for developers changing `src/tvgw/tshark.py` or `src/tvgw/clienthello.py`, and for the owner checking a new tshark on the Pi. What the extractor does is in [docs/extractor.md](../../docs/extractor.md).

## What is here

| Path | What it is |
|---|---|
| `build.py` | The builder. It writes everything below from code, byte by byte, so the corpus needs no capture and carries no site identifier. |
| `record.py` | Runs the installed tshark over every pcap with the command ingest uses and writes its rows to `tsv/tshark-<version>/`. |
| `pcap/<case>.pcap` | One case each: Ethernet, IPv4 and TCP or UDP frames from the TV (`10.10.10.17`) to documentation-range servers. |
| `tsv/synthetic/<case>.tsv` | The rows tshark should print for the pcap, written by `build.py` from the field formats of tshark 4.0 and 4.4. |
| `tsv/tshark-<version>/<case>.tsv` | The rows a real tshark printed, once someone has run `record.py` and committed them. None is committed yet. |
| `expected.json` | Per case: why it exists, and the hellos `tshark.extract` must return (time, ports, name, ECH flag, JA4 and its raw form, transport, partial). |

## The cases

| Case | What it pins |
|---|---|
| `spec-example` | FoxIO's worked example from JA4.md. Its fingerprint, `t13d1516h2_8daaf6152771_e5627efa2ab1`, is quoted from the spec, not computed. |
| `chrome-pq-split` | A post-quantum hello (an ML-KEM key share) over two TCP segments, both kept, the name in the second: reassembled, named and fingerprinted. GREASE in the ciphers, extensions and versions; the GREASE ECH extension Chromium always sends. |
| `chrome-pq-split-first-only` | The same hello with only its first segment kept: a partial hello without a name, stored in `tls_noname`. |
| `chrome-pq-early-first-only` | Only the first segment kept, with the name in it: a partial hello with its name and no JA4. |
| `firefox-like` | `delegated_credentials` before `signature_algorithms` and `signature_algorithms_cert` after: three lists under one tshark field, of which JA4 takes the middle one. |
| `no-sni` | No `server_name` and no ALPN: JA4's `i` and `00`. |
| `ech-cloudflare` | Real ECH as the wire shows it: the extension and the provider's public name. |
| `tls12-odd-alpn` | TLS 1.2 with neither `supported_versions` nor `signature_algorithms`, a first ALPN value that is not alphanumeric at its ends, and the hello sent twice. |
| `quic-initial` | A QUIC v1 Initial, encrypted with the keys its connection ID gives anyone (RFC 9001 section 5.2). |

## How it is used

`tests/unit/test_corpora.py` checks four things on every machine: the committed files equal a fresh build; the synthesised rows, through `tshark.parse_row` and `tshark.dedupe`, give the expected hellos; every committed `tsv/tshark-<version>/` gives them too; and the pcap bytes, through `clienthello`, give the expected name and JA4. Where tshark is installed it also runs `tshark.extract` on each pcap and compares. That last test is the differential the R&D report asks for ([state of the art, section 11](../../docs/research/state-of-the-art-2026-10.md#11-testing-and-quality)): the same input through tshark and through our own parser.

The expected JA4 strings come from a second implementation inside `build.py`, written from the spec and importing nothing from `tvgw`.

## Changing the corpus

1. Edit `build.py`: add a case to `cases()`.
2. Run `python3 tests/corpora/build.py` from the checkout. The QUIC case needs the `cryptography` package; without it, the committed QUIC files are left as they are.
3. Run `make gate`. Commit the builder and its output together.

## Recording a real tshark

On the Pi, as an ordinary user, from a checkout:

```sh
PYTHONPATH=src python3 tests/corpora/record.py
PYTHONPATH=src python3 -m pytest -q tests/unit/test_corpora.py -p no:cacheprovider
```

The first command writes `tsv/tshark-<version>/`. The second must pass with the tshark tests run, not skipped. Commit the new directory: from then on every machine checks that tshark version's rows, so a field that prints differently in a later version fails a test instead of losing hellos.
