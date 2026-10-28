# TV profiles

A profile is everything vendor-specific about a TV, kept as data so that a different TV is a different file, not a different program. Isolation, capture, the store, `tvgw verify` and the brief do not change between vendors. The profile says which names are the TV doing its job, which are surveillance, which must never be blocked, and how to filter the vendor's file service.

The active profile is the `PROFILE` setting in `/etc/tvgw/tvgw.conf` (default `lg-webos`). `tvgw profile` prints what it knows and lints it.

## Files

| File | What it is |
|---|---|
| `__init__.py` | Makes this a package, so the profiles ship inside the installed wheel. |
| `lg-webos.toml` | The LG webOS profile: metadata, categories, must-allow hosts, AdGuard blocklists, the URL filter, and the reference tables for webOS generations, hardware and a checklist. |
| `lg-webos.rules` | Its companion AdGuard custom rules, one per line, each group under a dated comment. |

`pyproject.toml` packages `profiles/*.toml` and `profiles/*.rules`. A profile is loaded by bundled name (`lg-webos`) or by a path to a `.toml` file, whose `.rules` file is the one beside it.

## What a profile contains

| Section | Used for |
|---|---|
| `[profile]` | `name`, `vendor`, `description`; `expected_categories` (allowed names in these are normal; others show in the brief); `clock_hosts` (lookups the TV must make to set its clock; `*` and `?` wildcards); `never_block_apex` (zones where a block at the apex has broken TVs). |
| `[categories]` | Category name to host patterns. Longest match wins; a pattern matches the host and its subdomains; `strip_prefixes` are removed from the front of a name before matching. No match is `Other`. |
| `[must_allow]` | `host = "why"`. Each becomes a generated `@@||host^$important` exception in AdGuard's rules (the modifier is what lets it win over a list's `$important` block; order decides nothing), and is checked by `verify`, the brief's red line and the hardware suite. |
| `[adguard]` | `filters`: the blocklists `tvgw adguard apply` makes sure are present and enabled. |
| `[url_filter]` | `hosts` rewritten to the gateway (one generated `||host^$dnsrewrite=<GW_IP>` rule each) and `block_regex` for nginx. Optional. |
| `[[generations]]`, `[[hardware]]`, `[checklist]` | Reference tables printed by `tvgw profile`. They do not change what is blocked. |

How `.rules` relates: AdGuard's custom rules are the generated must-allow exceptions, the generated URL-filter rewrites, then the `.rules` file, comments (`!`) and blank lines dropped, duplicates removed (`Profile.adguard_rules()`). The file holds the blocks and the regex rules. The file must exist beside the TOML; an empty file is fine (the capture-phase profile), a missing or unreadable one is an error, because a profile loaded without its rules would be a clean lint and a TV that reaches everything.

## The lg-webos profile: where it came from

The profile was built from an LG CX (2020, webOS 5, firmware 04.64) observed in October 2026, plus the sources named in the TOML header: the HaGeZi LG webOS list, Perflyst's Smart-TV list, hugobatista/lg-tv-ad-block, the IMC 2024 ACR study (arXiv 2409.06203), and community captures of newer webOS generations gathered on 2026-10-26.

Some things in it were learned the hard way:

- The clock comes from LG's SDP reply (`X-Server-Time`), not NTP. `clock_hosts` are the country SDP hosts only (`??.lgtvsdp.com`, `??.nextlgsdp.com`), because `rdx2.lgtvsdp.com` under the same zone is telemetry.
- Several must-allow hosts are CNAMEs into `aws-prd.net`, which also carries ad hosts. The `aws-prd.net` rules are therefore regexes on the specific CNAME targets, never the zone.
- `us.lgrecommends.lgappstv.com` is must-allow: the Content Store fails without it.
- Blocking the GFTS hosts broke an app update, which is why they are URL-filtered instead (see [../../../deploy/nginx/README.md](../../../deploy/nginx/README.md)).

### Evidence grades

Every `[[generations]]` and `[[hardware]]` row has a `confidence`:

| Grade | Meaning |
|---|---|
| `observed` | Seen on a set this project ran: packets captured, firmware read. Only an observed generation gets `verified = true`. In `lg-webos` the observed rows are webOS 5 and the CX/BX hardware row. |
| `community` | Independent reports agree (forum posts, issue trackers, teardowns). |
| `spec` | The vendor's own product pages say so. |
| `low` | One report, an unclear source, or a guess; the row's `notes` say why. |

The code does not check the grade, and a missing one defaults to `low`. In `[categories]` and `.rules`, entries never seen on the CX are marked "unverified" in a comment. In `.rules`, each group of rules carries the date and the evidence, and rules that were tried and rejected stay as comments so nobody tries them again (Prime Video's ad-pod host, for one). Why the profile works this way: [../../../docs/design-decisions.md](../../../docs/design-decisions.md#15-blocklist-entries-come-from-evidence-with-grades).

## How to change it

1. Edit the TOML or the `.rules` file. Give every new block a dated reason, and note the cost if blocking it breaks a feature.
2. `tvgw profile --profile src/tvgw/profiles/lg-webos.toml` prints `rules lint: clean` or the problems and exits 1. The lint refuses a block (hosts syntax such as `0.0.0.0 host` included, and a `$dnstype` rule that withholds any type but HTTPS, SVCB or AAAA), a `$dnsrewrite` rule or a regex rule (matched case-insensitively) that covers a must-allow host, a regex that does not compile, a rule in any form but `||host^`, a one-name hosts line or a `/regex/`, a block at a `never_block_apex` apex or a wildcard-only chain above it (`*.lgtvsdp.com`), an exception that sits above or equals a blocked name, and a URL-filter host that covers a must-allow host. `tvgw adguard diff` and `apply` run the same lint first and refuse a profile that fails it.
3. `make gate`. The unit tests include the lint and the categorizer cases in `tests/unit/test_profile.py`.
4. Deploy and run `sudo tvgw adguard diff`; it must exit 0.

If you change `block_regex` or `hosts`, change `deploy/nginx/tvgw-gfts.conf` and `deploy/nginx/stream.conf` to match: `tests/unit/test_profile.py::test_nginx_conf_matches_the_profile` fails `make gate` until the regex, the `server_name` list and the passthrough map agree with the profile, and the hardware suite checks the installed file after a deploy.

## Gotchas

- Never write `@@` exceptions for must-allow hosts or `$dnsrewrite` rules for URL-filter hosts in `.rules`; both are generated (the exceptions with `$important`), and a hand-written copy is dropped as a duplicate.
- AdGuard matches rules against CNAME targets as well as the queried name. A broad block can catch a must-allow host through its CNAME even when the lint is clean. The brief's red line catches that.
- `tools.google.com` and `stun.services.mozilla.com` are categorized `3rd-party ads` (the unit test pins it) and blocked in `.rules`: the browser engine's own pings, no TV function. Blocked lookups count in the category table; only an allowed name outside the expected categories shows as "allowed, outside the expected categories", so these appear there only if a rule stops blocking them.
- The generated `$dnsrewrite` rules follow `GW_IP`; the nginx files, the firewall and dnsmasq still hardcode `10.10.10.1`, so changing `GW_IP` alone moves the rewrites and not the listener.

Writing a profile for another vendor: [../../../docs/adding-a-profile.md](../../../docs/adding-a-profile.md).
