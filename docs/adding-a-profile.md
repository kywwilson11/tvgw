# Adding a profile for another TV vendor

Isolation, capture, the store, `tvgw verify` and the brief are vendor-neutral. A profile supplies what is vendor-specific: which names are the TV doing its job, which are surveillance, which must never be blocked, and how to filter the vendor's plain-HTTP file service if it has one. The bundled example is `src/tvgw/profiles/lg-webos.toml` with its companion `lg-webos.rules`.

Do this in two phases. First capture, with nothing blocked. Then write the policy from what you saw.

## Phase 1: capture first

### 1. A skeleton profile that blocks nothing

Create `src/tvgw/profiles/acme-tv.toml` (use your vendor's name):

```toml
[profile]
name = "acme-tv"
vendor = "Acme"
description = "Acme smart TVs (capture phase)"
expected_categories = ["Streaming", "Infra"]
clock_hosts = []
never_block_apex = []

[categories]
strip_prefixes = []
Streaming = ["netflix.*", "googlevideo.com"]
Infra = ["ocsp.*", "digicert.com"]

[must_allow]

[adguard]
filters = []
```

Create an empty `acme-tv.rules` beside it. Set `PROFILE=acme-tv` in `/etc/tvgw/tvgw.conf` and run `make deploy`. Isolation, DNS redirection and capture all work with this profile. Nothing is blocked. If AdGuard Home came with a default blocklist after its wizard, turn it off in the UI for a clean observation; `tvgw adguard apply` never touches lists it does not own.

`tvgw adguard apply` replaces AdGuard's custom rules with the profile's, so the empty `.rules` file also clears any rules left over from another profile.

### 2. Observe for 48 hours

Run `tvgw brief` each day. On the Pi, `sudo tvgw ingest` loads new data on demand, but TLS names come from finished hourly pcaps and arrive up to about two hours late.

Do these things deliberately, and write down the clock time of each:

- **Cold boot with the power pulled**, not standby. The boot sequence shows the clock source, firmware check, account and provisioning hosts, and anything that phones home before you touch the remote.
- **Open the app store, install an app, update an app.** Note which names carry the downloads and which carry store metadata.
- **Launch each app you use** and play something for a few minutes. Note the video CDN names and the telemetry that starts with the app.
- **Leave the TV in standby overnight.** The brief's "While off/asleep" line shows what it does when you are not watching.
- **Change a setting that should matter** (a privacy toggle) and see whether new names appear. `tvgw new-hosts 2h` after each step attributes names to actions.

Useful queries:

```sh
tvgw new-hosts 2d          # everything first seen, with category and counts
tvgw allowed 2d            # all allowed names outside the expected categories (everything, at first)
tvgw top-upload 2d         # who the TV sends bytes to
tvgw host NAME             # one name in depth
tvgw sql "select datetime(t,'unixepoch','localtime'), qname from dns order by t limit 200"
```

The last one lists the earliest DNS lookups in the store. To read one boot, give it a start time (local time):

```sh
tvgw sql "select datetime(t,'unixepoch','localtime'), qname, blocked from dns where t >= strftime('%s','2026-10-27 08:00','utc') order by t limit 200"
```

### 3. Find the clock hosts

Some TVs have no battery clock and take the time from a vendor server. Block that server and the clock resets, then TLS fails everywhere. Look at the lookups just after power-on, before the first TLS connection: the clock source is among the first few vendor names. To confirm, block the candidate for one boot and see whether the TV's clock goes wrong. This can break the TV until you unblock and restart it, so do it last and be ready to undo it.

Note which hosts set the clock; they go in `clock_hosts` and in `[must_allow]`.

## Phase 2: write the profile

### `[profile]`

| Key | Meaning |
|---|---|
| `name`, `vendor`, `description` | Shown by `tvgw profile`. `name` must match the file name and the `PROFILE` setting. |
| `expected_categories` | Categories that are the TV doing its job. Defaults to `["Streaming", "Infra"]`. An allowed name in any other category shows up in the brief under "Allowed, outside the expected categories", and counts toward DNS oddities. |
| `clock_hosts` | Patterns for the lookups the TV must make to set its clock. `*` matches any run of characters and `?` exactly one. They match the whole query name, case-insensitively. Subdomains are not matched implicitly, so a pattern like `??.example.com` matches `us.example.com` but not `telemetry.example.com`. If any host is listed, the brief raises a red line when one is blocked, or when the TV was on and none was looked up. An empty list turns the checks off. |
| `never_block_apex` | Zones where a block at the apex has broken TVs, because the same zone carries delivery and telemetry. The lint refuses a block rule for exactly these names. |

### `[categories]`

Each key is a category and each value is a list of host patterns. `strip_prefixes` is reserved: it lists regional prefixes (`eu-`, `aic.`) removed from the front of a name, once, before matching.

How a name is categorized:

- Patterns are lower-cased and use shell-style wildcards (`*`, `?`, `[...]`). `*` also matches dots.
- A pattern matches the host itself or any subdomain of it. `example.com` matches `example.com` and `a.b.example.com`.
- Longest match wins. The score is the pattern's length without `*`. On a tie, the earlier pattern in the file wins.
- No match gives `Other`. Do not define a category called `Other`.

So `peacocktv.com` can be Streaming while `ingest.webcol.sdp.peacocktv.com` is a more specific 3rd-party ads entry. Order categories the way you want the legacy report to list them.

Name a category `ACR` if the vendor has one. The hardware suite checks that no ACR-category name was answered in the last day. With no `ACR` category the check passes without checking anything.

### `[must_allow]`

A table of `host = "why"`. These are the names that broke somebody's TV when blocked: clock, firmware updates, connectivity check, store feed and API. The reason is for the next person.

Every must-allow host becomes an exact exception rule `@@||host^`, generated and placed first in AdGuard's custom rules. Never write these in the `.rules` file. They are also checked by `tvgw verify` (`resolver_must_allow`), by the brief's red line, and by the hardware suite.

### `[adguard]`

`filters = [{ name = "...", url = "..." }]`. `tvgw adguard apply` makes sure each list exists and is enabled, matching by URL and setting the name. Other lists in AdGuard are left alone. Prefer curated, vendor-specific lists, and start with fewer than you think you need; the capture is the evidence, a list is a starting point.

### `[url_filter]` (optional)

Some vendors serve content over plain HTTP from hosts that mix wanted and unwanted traffic, so DNS cannot separate them (LG's file service carries app packages and the ACR config file alike). The pieces:

- `hosts`: names AdGuard answers with the gateway address. Put `||host^$dnsrewrite=10.10.10.1` rules in the `.rules` file, one per host. A host cannot be both must-allow and in `url_filter.hosts`; the lint says so.
- `block_regex`: matched case-insensitively against the request URI. The profile's copy is used by tests (`UrlFilter.blocks`).

`tvgw verify` checks that each host in `hosts` resolves to the gateway. Everything else is in `deploy/nginx/tvgw-gfts.conf` and `deploy/nginx/stream.conf`, which are written for LG and are not generated from the profile: the real `$request_uri ~* "..."` regex, the `server_name` list and host check, and the TLS passthrough map. For a new vendor, copy and edit those by hand, and keep the regex in the nginx file identical to `block_regex`. Keep the `if ($request_uri ~* "...")` shape, because the rule-history ingest reads the regex from that line.

Leave the section out if the vendor has no such service. Note that two hardware tests assume a URL filter exists (see below).

### `[[generations]]`, `[[hardware]]`, `[checklist]` (optional)

Reference tables printed by `tvgw profile`. They do not change what is blocked.

| Table | Keys |
|---|---|
| `[[generations]]` | `webos` (the OS release, as a string; the key name is LG's), `years`, `codename`, `models`, `firmware_major`, `verified`, `clock_hosts`, `lan_api`, `dns_bypass`, `hardcoded`, `notes`, `confidence`. `tvgw profile --webos V` or `--firmware F` picks one (webOS major first, then firmware major). |
| `[[hardware]]` | `models` (shell patterns on the model number, upper-cased, spaces removed), `year`, `far_field_mic`, `assistants`, `notes`, `confidence`. The first matching row wins, so put specific rows before general ones. An unknown model is reported as "treat it as having a microphone until checked". |
| `[checklist]` | `topic = ["step", ...]`. Printed when you pass `--model`. |

The output text of `tvgw profile` says "webOS" and "Magic Remote"-style wording in places. That is LG phrasing in `cli.py`, not in your data.

### Evidence grades

Grade every generation and hardware row with `confidence`:

| Grade | Use it when |
|---|---|
| `observed` | You captured it on a set you own: packets seen, firmware read. Use `verified = true` on a generation only for this. |
| `community` | Independent people reported the same thing (forum posts, issue trackers, teardown notes). Cite the sources in the file header. |
| `spec` | The vendor's own product page or documentation says so. |
| `low` | One report, an unclear source, or a guess. Say so in `notes`. |

The code does not validate the grade, and the default is `low`. In `categories` and `.rules`, mark entries you have not seen on your own set with a comment such as `unverified here`, as the LG profile does.

## The companion `.rules` file

AdGuard syntax, one rule per line, in `src/tvgw/profiles/<name>.rules`. Lines starting with `!` are comments. A missing file is not an error: the lint and `apply` see an empty list, so check the file name.

Conventions:

- Group rules under a comment with the date and the reason: what the host is, how you saw it, what it cost to block. `! Peacock's first-party telemetry ingest. Verified 2026-10-25: playback fine with it blocked.`
- Record what you tried and rejected, so nobody repeats it.
- Note the cost of a block when one exists (a feature that stops working).
- The exceptions for `[must_allow]` hosts are generated; do not add them here.
- `$dnsrewrite` rules for URL-filter hosts go here.

## Lint

```sh
tvgw profile --profile src/tvgw/profiles/acme-tv.toml
```

On a machine without `/etc/tvgw/tvgw.conf`, the default settings are used. The command prints `rules lint: clean` and exits 0, or prints the problems and exits 1. It refuses:

- a block rule that covers a must-allow host,
- a block rule at exactly the apex of a `never_block_apex` zone,
- an exception rule that sits above a blocked name (AdGuard exceptions outrank blocks),
- a host that is both must-allow and rewritten by the URL filter.

Regex rules and rules it cannot parse are not checked. CI runs the lint through the unit tests.

With `--model`, the command also prints the hardware row and the checklist.

## Unit tests

Add them to `tests/unit/test_profile.py` (or a new file next to it), and use real captured names, not invented ones.

- **Categorizer cases**: a parametrized `(host, category)` list, as `test_lg_categories` does. Include a longest-match case (a specific host beating its parent zone), a prefix-stripped case, a wildcard case, and a name that must fall through to `Other`.
- **Lint clean**: `assert profile.load("acme-tv").lint() == []`, plus a check that the generated exceptions appear in `adguard_rules()` ahead of the blocks.
- **Must-allow**: the clock and update hosts are present, with reasons.
- **URL filter**: `UrlFilter.blocks()` on real URIs, both blocked and passed, if you have one.
- **Clock hosts**: a test like `test_telemetry_under_the_clock_zone_is_not_a_clock_host` in `tests/unit/test_brief_sections.py`, so a telemetry name under the same zone does not satisfy the clock check.
- **Tables**: model and generation lookups, with a check that every `confidence` is one of the four grades.

Run `make gate`.

## Hardware tests

`tests/hardware/test_gateway.py` runs on the Pi against the live gateway. Most of it is vendor-neutral and driven by the profile.

Vendor-neutral, and it works as is:

- services and timers are up; the key firewall rules are present; the DoH bootstrap addresses are in the block set,
- the IPv6 guard, the per-interface forwarding switches, the TV's route out, `nftables.service` masked,
- must-allow names resolve and were never blocked since the exceptions were applied,
- no ACR-category name was answered (needs an `ACR` category),
- `tvgw adguard diff` is clean; `tvgw verify` passes,
- the store is fresh, sound and at the current schema; a second ingest adds nothing,
- capture is live and the disk is healthy; state files are not world-readable,
- nginx listens only on the TV-facing address; the DHCP reservation exists; the DNS redirect counters tick.

LG-specific, or assuming a URL filter. Adapt or skip for another vendor:

- `test_blocked_names_resolve_to_zero` hardcodes three LG hostnames. Replace them with names your profile blocks.
- `test_url_filter_names_point_at_the_gateway` asserts the profile has a `[url_filter]`; it fails without one.
- `test_url_filter_blocks_and_passes` and `test_tls_passthrough_reaches_the_real_host` use LG's file-service URLs and host names.
- `test_tv_lan_api_reachable_or_asleep` uses the LG LAN API reader, and the second half of `test_tv_has_its_dhcp_reservation_and_acr_is_off_in_the_store` looks for the `option.livePlus` reading. The DHCP half is neutral.

## What else is LG-specific

- `tvgw tvcheck` reads the LG webOS LAN API (`src/tvgw/lgwebos.py`). `tvgw-analyze` runs it hourly. For another vendor it finds no TV to read, and the hourly history file records `unreachable` for every hour. In the brief, the TV line then shows `unreachable` readings and the "While off/asleep" line counts all of that day's traffic as off-hours traffic. Ignore both, or write a reader (below).
- The red line for a TV that was on without a clock lookup needs an `Active` reading, and the firmware-change section needs a `firmware` setting. Neither fires without a reader. The store reads `/var/lib/tvgw/tvcheck-history.log`, one line per hour (`YYYY-MM-DD HH:MM power app`), and `/var/lib/tvgw/tvcheck.txt` (`key = value` lines under a `read YYYY-MM-DD HH:MM` header) for settings. A reader for your TV that writes the same files restores all of it.
- The nginx files, the firmware-fallback address in `tvgw-apply`, and the fixed gateway plan (10.10.10.0/24, with `10.10.10.1` also inside the `.rules` rewrites) are written for the LG deployment.

## Checklist before you deploy

1. `tvgw profile --profile ...` exits 0.
2. `make gate` passes.
3. `make deploy`, then `sudo tvgw adguard diff` exits 0 and `sudo tvgw verify` is all OK.
4. Block in small batches. After each, use the affected function, wait five minutes, read `tvgw retries 1d` and `tvgw rules`, and keep the dated reason in the `.rules` file.
