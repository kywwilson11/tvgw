# The `tvgw` package

The Python side of the gateway: parsers for every log the Pi writes, the SQLite store, the hourly ingest, the read-side queries behind the brief, `tvgw verify`, AdGuard Home as configuration, and the CLI. The firewall and capture are shell and systemd (see [../../deploy/README.md](../../deploy/README.md)); this package reads what they produce.

The big picture is in [../../docs/architecture.md](../../docs/architecture.md).

## Module map

| Module | Role |
|---|---|
| `__init__.py` | Package docstring and `__version__`. |
| `config.py` | `Settings`: the paths and settings everything uses, from `/etc/tvgw/tvgw.conf`. Only the keys in `CONF_KEYS` are read from the file. |
| `db.py` | The schema (version 2), `connect()` (writers apply the schema; readers open `mode=ro`), `meta` helpers, `counts()`. |
| `logtail.py` | Reads new complete lines from a growing log and survives `copytruncate` and rename rotation. |
| `conntrack.py` | Parses `conntrack -E -e DESTROY -o timestamp,extended` lines into `Flow`. |
| `adguard.py` | Parses AdGuard's `querylog.json` records into `DnsRecord`; RFC 3339 times; reads `user_rules` from the YAML. |
| `dnsmsg.py` | Decodes A, AAAA and CNAME answers from a raw DNS message (AdGuard stores them base64). |
| `dnsq.py` | Sends one plain UDP DNS question. Used by `verify`, the AdGuard readiness wait and the hardware tests. |
| `gfts.py` | Parses the nginx URL-filter log; extracts `biz_code`. |
| `tshark.py` | The one tshark pass per pcap: TLS hellos, plain-HTTP requests and SYNs. Drops to `nobody` when run as root. |
| `pcaps.py` | The pcap directory as a store: which file tcpdump holds open (from `/proc`) and which files are finished. |
| `names.py` | Which names are public internet names; registrable domain; Shannon entropy for random-looking labels. |
| `profile.py` | Loads a profile (TOML plus `.rules`), categorizes names, generates the AdGuard rules, lints them, and looks up generations and hardware. |
| `ingest.py` | Every source into the store, each in its own transaction; the `hosts` refresh; pruning; the ingest lock. |
| `queries.py` | Read-side queries. `window_report()` builds the brief's data; `brief()`, `weekly()` and `latest()` are its three shapes; `red_lines()`. |
| `verify.py` | The checks behind `tvgw verify`, and `record()` for the verdict and the firewall counters. |
| `adguardcfg.py` | `desired()`, `plan()`, `changes()`, `apply()`: AdGuard Home's YAML from the profile and settings, validated and rolled back on failure. |
| `lgwebos.py` | Reads the LG TV's settings over its LAN API (optional `bscpylgtv` dependency). Read-only. |
| `cli.py` | `argparse` wiring, the `cmd_*` functions, `table()`, `render_brief()`, and `clean()` for text from the TV. |
| `profiles/` | The bundled profiles. See [profiles/README.md](profiles/README.md). |

## How data flows through it

```
flows.log ── logtail ── conntrack.parse_flow ──┐
querylog.json ── logtail ── adguard.parse ─────┤
pcap/ ── pcaps.finished ── tshark.extract ─────┤
gfts.log ── logtail ── gfts.parse_line ────────┼── ingest.run ── db (tvgw.db) ── queries ── cli
tvcheck-history.log, tvcheck.txt ──────────────┤                      ^
journalctl -k (tvgw-oddport) ──────────────────┤                      │
nginx conf, block4.txt, AdGuard YAML (rules) ──┘     verify.record ───┘
```

Parsers are pure functions: a line in, a dataclass or `None` out. `ingest.py` is the only module that writes the base tables. `queries.py` returns plain tuples and dicts, and `cli.py` renders them; `--json` prints the same dicts.

Everything that touches the Pi is a parameter: tshark is `extract=`, `/proc` is `live=`, journalctl is `oddport_lines=`, `verify.check()` takes `run`, `read` and `resolve`, `adguardcfg.apply()` takes `control`, `ready` and `check`. The unit tests pass fakes. Keep new code in that shape.

## How to change or extend it

**Add a query.** Write a function in `queries.py` that takes `conn`, `since` and `until` (use `_until(until)` so `None` means open-ended) and returns tuples. Test it on hand-seeded rows in `tests/unit/test_queries_gaps.py`.

**Add a brief section.** Compute it in `window_report()` into a new key of `o`, so the JSON output carries it. Render it in `cli.render_brief()`, passing every string from the TV through `table()` or `clean()`. Then update the golden brief in `tests/unit/test_cli_golden.py`: run `TVGW_GOLDEN_OUT=/tmp/brief.txt python -m pytest -k brief_text`, review the file, and paste it into `BRIEF`. A new red line goes in `red_lines()` and gets a runbook row in [../../docs/operations.md](../../docs/operations.md#red-lines).

**Add a `verify` check.** Append a `Check(name, ok, detail)` in `verify.check()`, using only the injected `run`, `read` and `resolve`. Script the command output in `tests/unit/test_verify.py`, for both a pass and a fail. Add a row to the checks table in the runbook.

**Add a CLI command.** Add a subparser in `build_parser()` with `set_defaults(fn=cmd_x)`. A command is `cmd_x(a, s, prof) -> int`, where the return value is the exit code. Read-only commands open the store with `_ro(s)`. Print tables with `table()`. Add a golden case to `GOLDEN` in `test_cli_golden.py` and a row to the README's CLI table.

**Show a new firewall counter in the brief.** The rule in `tvgw-apply` needs both `counter` and `comment`. Add `(comment prefix, label)` to `queries.FW_LINES`; the first matching prefix wins.

**Add an ingest source.** Write a pure parser, an `ingest_x(conn, s)` that tails with `_tail(conn, "x", path)`, and a `step("x", ...)` in `run()`. Add the name to `SOURCES` and, if the brief should say when it was not read, to the `rows` map in `queries.coverage()`.

## Gotchas

- **Schema changes.** The schema is applied on every writer open with `CREATE ... IF NOT EXISTS`, so adding a table or index is safe. Changing a column is not; bump `SCHEMA_VERSION` and handle old files yourself. The hardware suite checks the stored version.
- **The AdGuard cursor key is `adguard`.** The source is called `dns` everywhere else. Renaming the key would re-read the whole query log.
- **tshark exit 2.** It means "cut short", which is normal for a file tcpdump just rotated, only when stderr says so. A file tshark could not open also exits 2. `extract()` raises in that case and ingest retries the pcap.
- **Rule comments are an interface.** `FW_LINES` and `verify`'s key-rule check match nftables comments and rule text. Change them together.
- **Categories are recomputed.** `hosts.category` is refreshed for every name on every ingest, and the brief categorizes at query time. A profile change applies retroactively.
- **Time.** Days are local calendar days. The unit tests pin `time.time` and `TZ=America/Chicago`; code that reads the clock another way escapes the freeze.
- **`hosts.notes`** is a free-text column that survives a rebuild of `hosts`. No command writes it.
- **Settings that are not read here.** `WAN_GW`, `URL_FILTER_RESOLVER`, `DOH_LIST_URL`, `PCAP_DAYS` and `PCAP_MAX_GB` are read only by the shell scripts. `GW_IP`, `STATE_DIR` and `DB_PATH` can be set for Python, but the shell side hardcodes `10.10.10.1` and `/var/lib/tvgw`.

Tests for all of this: [../../tests/unit/README.md](../../tests/unit/README.md).
