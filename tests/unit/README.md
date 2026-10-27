# Unit tests

pytest, no gateway needed. The rule: fixtures are real lines captured on the Pi, with site identifiers replaced, and anything that touches the system is a parameter the test fills with a fake.

Run them with `make test`, or `make gate` for ruff, the format check and the tests together (what CI runs).

## The shared fixtures (`conftest.py`)

| Fixture | What it gives you |
|---|---|
| Constants (`FLOW_TCP`, `DNS_BLOCKED`, `GFTS_TV_BLOCKED`, `ODDPORT_LINE`, `ADGUARD_YAML`, `NGINX_CONF` ...) | Verbatim conntrack, query-log, nginx and kernel lines, plus lines from another client that must be ignored. All timestamps fall on 2026-10-26 in Chicago time. |
| `chicago_time` (autouse) | `TZ=America/Chicago` for every test, so day boundaries do not depend on the CI machine. |
| `frozen_now` (autouse) | `time.time()` returns `NOW`, 2026-10-26 10:00 CDT, just after every fixture timestamp. Without it, rule history, `last_run` and the prune cutoff would move with the calendar, and the suite would start failing once the fixture day was a year old. |
| `fake_live` (autouse) | `pcaps.live_files` answers that `tv-20261026-0900.pcap` is the file tcpdump holds open. The fake gateway runs no tcpdump and has no `/proc`; a test that wants another answer passes `live=` to `ingest.run`. |
| `EMPTY_PCAP` | The 24-byte pcap global header: a capture with no frames, which is what a pcap file in the fixture tree should be. |
| `UNITS`, `exec_lines()`, `capture_argv()` | The deployed unit files, read the way systemd reads them: continued lines joined, `%%` unescaped, words split with shell quoting. |
| `lg` | The bundled `lg-webos` profile. |
| `gateway` | A fake gateway tree under `tmp_path`, and a `Settings` that points at it. |
| `fake_extract` | Stands in for tshark. Returns TLS hellos, HTTP requests and SYNs, including rows from other sources, and fails if asked to read anything but the finished pcap. |
| `fake_oddport` | Stands in for journalctl. Honors `--since` the way the real one does. |

The `gateway` tree holds one hour of plausible data: `log/flows.log`, `querylog.json` ending in a partial record, `pcap/` with a finished file and the one "still being written", `log/gfts.log`, `state/tvcheck-history.log` and `state/tvcheck.txt`, `AdGuardHome.yaml`, `tvgw-gfts.conf` and `block4.txt`. A typical test ingests it:

```python
ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
```

## Files

| File | Covers |
|---|---|
| `test_conntrack.py`, `test_dnsmsg.py`, `test_adguard.py`, `test_gfts.py`, `test_tshark.py`, `test_logtail.py`, `test_names.py`, `test_config.py` | One parser or helper each, from verbatim lines. |
| `test_parsers_gaps.py` | Boundaries and defaults across the parsers, the profile and the store. |
| `test_pcaps.py` | The pcap directory: which file tcpdump holds open, read from a fake `/proc` tree, and which files are finished. |
| `test_deploy_units.py` | The systemd units as text: the pcap name pattern, `TZ=UTC` and why (both 01:20s of the fall-back night format to one local-time name), the analyze unit's OOM score, and no stray `%` or `$` in any Exec line. |
| `test_deploy_files.py` | The shell jobs as text: `bash -n` on each script, the tab-separated TV power history line, the `SETTLE` gate on finished days and weeks. |
| `test_capture_filter.py` | The deployed capture filter run through tcpdump on a synthetic hour; skipped where tcpdump is not installed. |
| `test_profile.py` | The LG profile: categories, URL filter, lint, generated exceptions, generations and hardware tables. |
| `test_ingest.py` | End-to-end ingest on the fake gateway: counts, idempotency, rotation, hosts, rules, pruning. |
| `test_ingest_gaps.py` | Cursors, persisted keys, limits, boundaries, locking. |
| `test_queries_cli.py`, `test_queries_gaps.py` | Queries and the brief on ingested and hand-seeded data. |
| `test_brief_sections.py` | Red lines and the evidence sections. |
| `test_cli_golden.py` | Golden output of every read-only subcommand and of the whole brief. |
| `test_cli_rich.py` | Rendering branches the fake gateway never reaches. |
| `test_verify.py` | `tvgw verify` against a scripted gateway, including the per-interface forwarding outage. |
| `test_adguardcfg.py` | Planning, diffing and applying AdGuard's config: managed keys only, the TV client entry, YAML 1.2 scalars, validation, and the readiness wait with rollback. |
| `test_lgwebos.py` | The LAN API reading: exit codes, cleaning of TV-supplied text, and a reading that never hangs. |

## Golden tests

`test_cli_golden.py` pins exactly what each command prints, so a change to a column is a visible diff. The expected outputs are inline: the `GOLDEN` list for subcommands and `BRIEF` for the full brief. To regenerate the brief after an intended change:

```sh
TVGW_GOLDEN_OUT=/tmp/brief.txt python -m pytest -k brief_text
```

That writes the rendered brief to the file (the test still fails until you update it). Review the file line by line, then paste it into `BRIEF`. For a subcommand, update its entry in `GOLDEN` by hand.

## Adding a parser test from a captured line

1. Copy the line exactly as the Pi wrote it, from `flows.log`, the query log, `gfts.log` or `journalctl -k`.
2. Replace site identifiers: the home-LAN and uplink addresses with documentation addresses such as `192.0.2.48`, any MAC with a fake one. Keep the TV's `10.10.10.17` and the gateway's `10.10.10.1`.
3. Put it in the test file as a constant (long lines are allowed in `tests/`), or in `conftest.py` if ingest tests need it too.
4. Assert on every field the parser returns, and add the malformed neighbor: truncated, wrong client, missing field.

## Mutation testing

`make mutmut` runs `mutmut run` and `mutmut results` with the settings in `pyproject.toml`: mutate `src/tvgw/`, test with `tests/unit/`, skip `src/tvgw/lgwebos.py`. It is slow and runs weekly in CI. For each surviving mutant, either add a test that kills it or decide the mutation is equivalent. The `*_gaps.py` files pin behaviors the first suite missed. `make clean` removes the `mutants/` directory.

## Gotchas

- Do not call `datetime.now()` or `time.time()` in a way that escapes the freeze; use the injected `now` parameters the queries take.
- `fake_extract` asserts on the pcap name. If you add a pcap to the tree, update it.
- Never add a real MAC, home-LAN address or ZIP code to a fixture.

More on the code under test: [../../src/tvgw/README.md](../../src/tvgw/README.md).
