# Unit tests

This folder holds the unit suite: pytest on lines captured on the Pi, with site identifiers replaced, and fakes for everything that touches the Pi. It runs on every `make gate`, on your workstation and in CI's `test` job. The kinds of tests and the map of seams to fakes are in [the tests overview](../README.md).

## Running them

On your workstation:

```sh
make dev                                         # once: the package, editable, with the dev extras
make test                                        # python3 -m pytest over tests/unit
make gate                                        # ruff check, ruff format --check, then pytest -q
python3 -m pytest tests/unit/test_profile.py -k lint    # one file, a subset of its tests
```

`pyproject.toml` sets `testpaths = ["tests/unit"]` and `addopts = "-q"`. Some tests skip on purpose:

- `test_capture_filter.py`, where tcpdump is not installed;
- `test_shell_syntax` in `test_deploy_lint.py`, for a shell the machine lacks;
- `test_an_unreadable_rules_file_does_not_load` in `test_profile.py` and the unreadable-settings test in `test_config.py`, when run as root, since root can read a mode-0 file;
- `test_cli_flags_override_the_conf_and_name_the_comparison_file` in `test_analyst.py`, without the `anthropic` package, which the `dev` extras do not install;
- in `test_corpora.py`, the tshark tests where tshark is not installed (it is on the Pi), the recorded-rows test until a `rows/tshark-<version>/` directory is committed, and the QUIC case's decryption without the `cryptography` package.

## Shared fixtures

`conftest.py` holds the fixtures and helpers every file shares.

| Name | Kind | What it gives |
|---|---|---|
| `fixed_time_zone` | autouse fixture | Sets a fixed `TZ` for every test and restores it after, so day boundaries do not depend on the CI machine. |
| `fake_live` | autouse fixture | `pcaps.live_files` answers that `tv-20261026-0900.pcap` is the file the capture holds open. The fake gateway runs no capture and has no `/proc`; a test that wants another answer passes `live=` to `ingest.run`. |
| `frozen_now` | autouse fixture | `time.time()` returns `NOW`, 2026-10-26 10:00 local time, after every fixture timestamp. Without it, rule history, `last_run` and the prune cutoff would move with the calendar, and the suite would start failing once the fixture day was a year old. |
| `gateway` | fixture | A fake gateway tree under `tmp_path` with one hour of data, and a `Settings` that points at it. |
| `quiet_flowlog` | autouse fixture | `ingest.journal_flowlog_lines` reports that conntrack lost no events. The test box has no `tvgw-flowlog` journal, and may have no `journalctl`; a test that wants losses passes `flowlog_lines=` to `ingest.run`. |
| `lg` | fixture | `profile.load("lg-webos")`, the bundled profile. |
| `capture_argv()` | helper | The arguments of one `Exec` line of a capture unit (`tvgw-pcap.service`'s dumpcap by default), with the drop-in's `${TV_IF}`, `${TV_NET}` and `${GW_IP}` filled in (`CAPTURE_ENV`, the shipped defaults), `%%` and `$$` unescaped, a `+` prefix dropped and words split as systemd splits them. |
| `exec_lines(unit)` | helper | Every `Exec*` line of a unit in `deploy/systemd/`, with continued lines joined the way systemd joins them. |
| `fake_extract(pcap)` | helper | The stand-in for tshark: TLS hellos, HTTP requests and SYNs, including rows from other sources, a LAN probe and its retransmission. It fails if asked for any pcap but the finished one, `tv-20261026-0800.pcap`. |
| `fake_oddport(since)` | helper | The stand-in for journalctl's kernel lines; it honors `--since` as the real one does. |
| `plan(conn, sql)` | helper | SQLite's `EXPLAIN QUERY PLAN` for a statement. |
| `statements(conn, fn)` | helper | The SQL a function ran, read back through SQLite's trace callback with its parameters bound, so the index tests explain the statements the code really runs. |
| `ROOT`, `UNITS` | constants | The checkout and its `deploy/systemd/` folder. |
| `TV`, `NOW`, `EMPTY_PCAP` | constants | The TV's address `10.10.10.17`, the frozen time `1793026800.0`, and the 24-byte pcap header of a capture with no frames. |
| `FLOW_TCP`, `FLOW_UDP`, `FLOW_OTHER_SRC`, `DNS_BLOCKED`, `DNS_ALLOWED`, `DNS_OTHER_CLIENT`, `GFTS_TV_BLOCKED`, `GFTS_TV_ALLOWED`, `GFTS_PI_TEST`, `ODDPORT_LINE`, `ADGUARD_YAML`, `NGINX_CONF` | constants | Verbatim conntrack, query-log, nginx and kernel lines, lines from other clients that must be ignored, and minimal AdGuard and nginx files. Every timestamp falls on 2026-10-26 local time. |

The `gateway` tree holds:

| Path under `tmp_path` | Contents |
|---|---|
| `AdGuardHome.yaml` | `ADGUARD_YAML`: a must-allow exception, a block and a rewrite. |
| `block4.txt` | One manual block. |
| `log/flows.log` | A TCP and a UDP flow from the TV, and one from the gateway. |
| `log/gfts.log` | A blocked and an allowed request from the TV, and a test request from the Pi. |
| `pcap/` | `tv-20261026-0800.pcap`, finished, and `tv-20261026-0900.pcap`, the one being written; both `EMPTY_PCAP`. |
| `querylog.json` | A blocked and an allowed TV query, another client's query, and a partial last record. |
| `state/tvcheck-history.log`, `state/tvcheck.txt` | Two hourly readings and one settings reading. |
| `tvgw-gfts.conf` | `NGINX_CONF`: the URL filter's regex line. |

A typical test ingests it:

```python
ingest.run(
    gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, gate_lines=no_kernel_lines, lock=False
)
```

`no_kernel_lines` is defined in each test file that needs it and returns no lines.

## Files

| File | What it covers |
|---|---|
| `conftest.py` | The shared fixtures above. |
| `corpus.py` | Not a test file: loads the corpus builder, `tests/corpora/build.py`, for `test_corpora.py`, `test_clienthello.py` and `test_tshark.py`. |
| `test_adguard.py` | AdGuard query-log records: blocked and allowed, reason codes, oddly typed fields, times; `user_rules` read from the YAML. |
| `test_adguardcfg.py` | AdGuard's config as code: planning, every owned key reported as drift, client reconciliation, YAML 1.2 scalars both ways, AdGuard's rejection text, the readiness wait, and `apply()` under fault injection (a failing stop, start or rollback, an empty file, a held lock, backup names, the signal mask). |
| `test_analyst.py` | The analyst: what the pack keeps and drops, the scrub, vetting like the profile lint, the request and the refusal, `--dry-run`, the key file, the settings and windows, the weekly pass. |
| `test_apply.py` | `tvgw-apply` run for real against stub commands (`nft`, `sysctl`, `ip`, `modprobe`, `flock`) with its paths under `tmp_path`: the shell logic and the rules it hands nft. |
| `test_apply_check.py` | `tvgw-apply --check` against the stub commands of `test_apply.py`: every load goes to `nft -c` and is printed, and nothing else happens (no load, delete or listing, no sysctl or route, nothing under `/run/tvgw`); a refused side table fails the check; the flag is exact; the capture table only with `CAPTURE_MODE=headers`; the virtual suite's variants render every counted rule. |
| `test_autoblock.py` | Autonomous blocking: the traffic-shape gate, the machine's rules file, the second model, the live canary, the hourly judge, `tvgw undo`, and the novelty gate that keeps quiet days free of requests. |
| `test_backup.py` | The checked store copy: `VACUUM INTO`, `quick_check` before the name, rotation, and a failure that leaves nothing. |
| `test_brief_sections.py` | The brief's red lines and evidence sections on a seeded store: clock hosts, unresolved flows, reverse-lookup sweeps, firmware, standby, the watchdog, Live Plus. |
| `test_capture.py` | Capture v2: the two capture units' conditions and dumpcap check run with `sh` and `dash`, the units side by side, `tvgw-apply`'s capture rule, `tvgw verify`'s capture checks, and a dumpcap ring through `/proc` and the ingest. |
| `test_capture_filter.py` | The deployed capture filter, compiled and run by tcpdump on a synthetic hour; skipped without tcpdump. |
| `test_clienthello.py` | The ClientHello byte parser and JA4: the spec's worked example, ALPN, version and empty-list rules, then properties over random hellos (shape, order and GREASE blindness, the 99 cap, fields and bytes agreeing, a cut hello never raising). |
| `test_cli_golden.py` | Golden output of the read-only subcommands and of the whole brief, and the `sql` command's read-only rules. |
| `test_cli_rich.py` | Rendering branches the fake gateway never reaches, and the usage errors for malformed time arguments. |
| `test_config.py` | Settings parsing: quotes, comments, types, exact switches, retention numbers, an unreadable file. |
| `test_conntrack.py` | conntrack `DESTROY` lines from `flows.log`, including the ones no store can hold. |
| `test_corpora.py` | The extractor against the golden corpus in [`../corpora/`](../corpora/README.md): the committed files against a fresh build, synthesised and recorded tshark rows, the pcap bytes through the parser, and the installed tshark where there is one (skipped without it). |
| `test_deploy_files.py` | The shell jobs as text: `tvgw-analyze`'s `SETTLE` gate and its tab-separated history line. Pieces of `install.sh` and `sync-install.sh` run under bash with a fake `systemctl` or `flock` and their paths moved under `tmp_path`: the first backup only, the restart of a long-running unit when what it read at start changed, and the order lock, rsync, install, suite with the lock handed down on descriptor 8. |
| `test_deploy_lint.py` | The deploy tree as a system: shell syntax by shebang, the key-rule text in `tvgw-apply`, the files the hardware suite compares, a start timeout on every oneshot, the workflow's shape, the one rsync list and its match with `.gitignore`, every write of `/opt/tvgw/src`, every install and every suite run holding the install lock, `tvgw-apply`'s defaults and `case` arms against `config.Settings`, pinned actions. |
| `test_deploy_units.py` | The units as text: UTC pcap names and why, the analyze unit's OOM score, no stray `%` or `$` in an `Exec` line. |
| `test_discover.py` | TV discovery from captured text with a fake network: leases, neighbors, DHCP names, port signatures and hostname hints, SSDP, `--write`, and the SSDP `LOCATION` pinned to plain http on the responder, and the SSDP answer hole in the guard table too. |
| `test_dnsgate.py` | The DNS gate feeder: the pcap stream, Ethernet, IPv4 and UDP framing, DNS answers, `nft` batches, the argv and the off switch. |
| `test_dnsmsg.py` | DNS message decoding from AdGuard's base64 answers, and the decoder's edges: reserved label types, overruns, escaped label bytes, the response code. |
| `test_encoding.py` | Every text file the package reads or writes names UTF-8, and the CLI's streams are UTF-8, run in a child interpreter pinned to an ASCII locale with UTF-8 mode off. |
| `test_extractor_store.py` | Schema 8: the migration of a schema 7 store, named and nameless hellos into `tls` and `tls_noname`, pruning, `queries.tls_noname`, flow names unchanged, the ECH canary's public names. |
| `test_fw_lines.py` | `queries.FW_LINES` against the counted comments in `tvgw-apply` ([design decision 13](../../docs/design-decisions.md#13-counters-not-logs-prove-the-firewall-held)). |
| `test_gate_ingest.py` | The DNS gate's kernel lines into the store, and the brief section they feed. |
| `test_gfts.py` | nginx URL-filter lines and `biz_code`; a sample substituted for every variable of the deployed `log_format`. |
| `test_guard.py` | (guard) The guard of design decision 42 as text and logic: the template's placeholders, transaction shape, rule order and unique comments; the unit's ordering and refused stop; `CO_TENANT_UNITS`; the co-tenant drop-in plan and writer; avahi's `deny-interfaces`; `tvgw guard`; `guard_present`, `guard_quiet`, `cotenants_denied`, `dnsmasq_caps` and `WARN`. |
| `test_guard_install.py` | (guard) install.sh's guard block against fake systemctl, ss, nft, nginx and tvgw: the guard reloads only when it changed, is missing or drifted from what its unit loaded; a sandbox dnsmasq or nginx will not serve with comes out again, once, and is not retried, while a daemon that fails without it too leaves no stamp; systemd is reloaded and avahi restarted only when `tvgw guard` printed a change. |
| `test_ingest.py` | End-to-end ingest on the fake gateway: counts, idempotency, rotation, hosts, rules, pruning, broken sources. |
| `test_ingest_gaps.py` | Ingest behavior the first suite never pinned: cursors, batches, the pcap budget and retries, LAN probes, TV readings, rule history, watermarks, pruning, vacuum. |
| `test_lgwebos.py` | The LG LAN API reading: exit codes, one printable line per value, and a read that never hangs. |
| `test_logtail.py` | Incremental reading across copytruncate and rename rotation. |
| `test_names.py` | Public names, LAN and public addresses as the firewall's `lan4` set sees them, reverse names, registrable domains, entropy. |
| `test_parsers_gaps.py` | Boundaries and defaults across the parsers, the profile and the store. |
| `test_packaging.py` | The .deb: its layout against what `install.sh` looks for, its dependencies, the four maintainer scripts run with stubs and their paths under `tmp_path` (preinst's AdGuard Home check, postinst's exits, including install.sh's own tv-lan step under its `ERR` trap with an `nmcli con up` that exits 4, the order prerm stops units in, what postrm removes and keeps), the lock, the pinned build backend and the wheelhouse builder with a fake pip and PyPI, the pinned uv of `make lock`, the release workflow's triggers, permissions and pins. |
| `test_pcaps.py` | The pcap directory: which file a capture process holds open, read from a fake `/proc`, which files are finished, and what retention may delete. |
| `test_profile.py` | The LG profile, loading and validation, the lint, the generated rules, the nginx files against the profile, the categorizer against its reference. |
| `test_profile_records.py` | Profile format v2: the `[[lan_api]]` and `[[privacy_setting]]` records and their provenance, the citation check for `.rules` files, and what `tvgw profile` prints. |
| `test_queries_cli.py` | Queries, the brief and the CLI on a store built from the fake gateway. |
| `test_queries_gaps.py` | Read-side queries on hand-seeded data: columns, day windows, limits, ordering, ECH, periodic connections. |
| `test_report.py` | The report path `tvgw-analyze` runs: ISO week bounds, the weekly by-day table, `tvgw report` through the CLI, the TV line as power runs. |
| `test_setup.py` | `tvgw setup` against a fake system: every step of the flow, the dry run, the unattended answers file, re-runs, refusals, the answers' TV identity always being the device picked, the install lock handed down as fd 8, pairing through an isolated virtualenv Python under umask 077; and the settings-file writer keeping comments, quoting and unknown keys while refusing what the shell or `config.load()` would refuse. |
| `test_supply_chain.py` | The repository's workflows as a system: every action pinned by commit with its tag named, token permissions at the top, no `pull_request_target` or `workflow_run`, no outsider-written text in a `run:` step, the self-hosted job's guard, the dependabot file, and the branch-protection settings the supply-chain page documents. |
| `test_tshark.py` | tshark rows into TLS hellos (named, nameless, partial, QUIC, with JA4 from the fields), HTTP requests and SYNs; the sandbox's properties; repeats dropped; and `extract` against a scripted tshark. |
| `test_tv_side.py` | The TV side from the settings file: the shell's `tvgw-net` block and `config.tv_side` run on the same cases and agree, the block is the same in `install.sh` and `tvgw-apply`, a second site's interfaces and subnet in every rule `tvgw-apply` hands nft, a subnet that would cover more than the TV refused before nft runs, the dnsmasq file for the defaults, `tvgw.service`'s stop path and the dispatcher with another `TV_IF`, a `TV_IF` edited before `tv-lan` moved (the off-port drop, the scoped masquerade, the stop when `GW_IP` is elsewhere, the old port's forwarding), `install.sh`'s WAN overlap check and its `tv-lan` create, move and stand-aside steps against a fake `ip` and `nmcli`, the capture's drop-in, and no deploy file spelling the defaults outside a default, a comment or a listed exception. |
| `test_vendor_profiles.py` | The DNS-only vendor profiles `samsung-tizen`, `roku` and `vizio-smartcast`, held to what an unverified profile must be: loadable, lint-clean, every rule cited and marked unverified, every must-allow host protected and never covered by a rule. |
| `test_verify.py` | `tvgw verify` against a scripted gateway: every check's pass and failure, the forwarding outage, recording, the counter series behind "Firewall held". |
| `test_virtual_harness.py` | The virtual gateway's parts that need no root ([tests/virtual](../virtual/README.md)): the matrix file and its rows against the script's counted comments, the conf, the variants read from the script's `case` arms, the counter parser, stale-namespace detection, the probes and stand-in services over loopback, and the `virtual` workflow's shape. |

The `*_gaps.py` files pin behaviors the first suite missed.

## Golden tests

`test_cli_golden.py` pins exactly what each command prints, so a change to a column is a visible diff. The expected outputs are inline: the `GOLDEN` list for subcommands and the `BRIEF` string for the whole brief. Lines are compared with trailing spaces removed.

To regenerate the brief after an intended change:

1. Write the rendered brief to a file. On your workstation:

   ```sh
   TVGW_GOLDEN_OUT=<file> python3 -m pytest tests/unit/test_cli_golden.py -k brief_text
   ```

2. Read the file line by line; the test still fails, because `BRIEF` is unchanged.
3. Paste the file into `BRIEF`, and run `make gate`.

For a subcommand, edit its entry in `GOLDEN` by hand.

## Adding a parser test

1. Copy the line exactly as the Pi wrote it, from `flows.log`, the query log, `gfts.log` or `journalctl -k`.
2. Replace every site identifier ([how these pages are written](../../docs/README.md)): a home-LAN or uplink address becomes a documentation address such as `192.0.2.48`, a MAC becomes `b4:b2:91:aa:bb:cc`, and host names go. Keep the TV's `10.10.10.17` and the gateway's `10.10.10.1`.
3. Put it in the test file as a constant, or in `conftest.py` when ingest tests need it too. Long lines are allowed under `tests/`.
4. Assert on every field the parser returns, and add the malformed neighbor: truncated, another client, a missing field.

## Mutation testing

`make mutmut` runs `mutmut run` and then `mutmut results`, with the settings in `pyproject.toml`: mutate `src/tvgw/`, test with `tests/unit/`, leave out `src/tvgw/lgwebos.py`. It is slow; CI runs it weekly and on a manual run ([how a change reaches the gateway](../../deploy/README.md#how-a-change-reaches-the-gateway)). For each surviving mutant, add a test that kills it or decide the mutation is equivalent. `make clean` removes `mutants/` and the mutmut cache.

## Gotchas

- Read the time through the injected `now` parameters the queries take. Code that reads the clock another way, such as `datetime.now()`, escapes `frozen_now`.
- `fake_extract` asserts on the pcap name. If you add a pcap to the tree, update it.
- The shared `lg` fixture is the bundled profile; a test of another profile loads its own.
- Never add a real MAC, a home-LAN address, a host name or a ZIP code to a fixture.
