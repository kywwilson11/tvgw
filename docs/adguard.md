# AdGuard Home

AdGuard Home is the resolver every lookup of the TV goes through. tvgw configures it as code ([design decision 6](design-decisions.md#6-adguard-home-is-configured-as-code)) and never bundles it ([design decision 25](design-decisions.md#25-adguard-home-is-a-checked-dependency-never-bundled)). This page owns what the gateway does around it: the blocklists that change on their own and how they are watched, the keys `tvgw adguard apply` owns, the schema ceiling, the upgrade path, the restart guard, the optional fallback resolver, and how long AdGuard keeps its own records. It is for the owner running the gateway and for anyone changing `src/tvgw/adguardcfg.py`. The decision behind it is [design decision 46](design-decisions.md#46-the-blocklists-are-watched-and-adguard-changes-only-on-purpose).

## Lists change on their own

The profile subscribes AdGuard to a few published blocklists (`[adguard] filters` in the profile). AdGuard re-downloads each one `filters_update_interval` hours after its last attempt, so the hour drifts, and it swaps in whatever the list's URL answers with `200 OK`. At the v0.107.79 tag its parser has no minimum rule count, so an empty `200` replaces a list with nothing, and any change of checksum counts as an update. A response other than `200` keeps the old file. Nothing in that path is reviewed: a list update is a change to what the TV may reach that no person and no watch of the gateway has looked at. Upstream mistakes happen: on 2026-09-11 HaGeZi shipped a zone-wide `nextlgsdp.com` block that broke clocks and the Content Store on webOS 6 and later, fixed about a day later.

The gateway watches that channel three ways today:

- **It owns the interval.** `tvgw adguard apply` writes `filters_update_interval: 24`, AdGuard's own default. A `0`, which AdGuard accepts since v0.107.78, would freeze every list silently; a UI edit to it is drift that the next apply puts back.
- **The sentinels.** Each HaGeZi list carries one name of its own that no other list carries. A list AdGuard has loaded answers its sentinel with `0.0.0.0`; a list that was emptied, or never loaded, answers it with an address. `tvgw verify` asks the resolver for the sentinel of every subscribed list it knows (`verify.SENTINELS`), every ten minutes.
- **List changes in the brief.** The store already records which list blocked each lookup (`dns.filter_id`). The brief's [List changes](reading-the-brief.md#list-changes) section names every name a list blocked for the first time in the window that the TV had resolved to an address in the 30 days before, and every name a list stopped blocking. A newly blocked name that carried content in the 14 days before its first block is a red line.

### The sentinels

| List in the profile | URL piece `verify.SENTINELS` matches | Sentinel |
|---|---|---|
| HaGeZi Pro (through AdGuard's registry) | `filter_48.txt` | `h4g3z1-pro.web.app` |
| HaGeZi LG webOS (through AdGuard's registry) | `filter_72.txt` | `h4g3z1-native-lgwebos.web.app` |
| HaGeZi DoH/VPN bypass (from jsDelivr) | `/adblock/doh.txt` | `h4g3z1-doh.web.app` |

HaGeZi publishes no document about the sentinels, so a renamed one upstream would make `list_sentinels` fail although every list is loaded. That is a loud false alarm, never an outage: check the list's file before acting. A list without a known sentinel (the Roku and Samsung native lists) is not checked.

On the Pi, the same question by hand (there is no `dig` on the gateway, so `tvgw verify` uses its own resolver code):

```sh
sudo tvgw verify | grep list_sentinels     # OK list_sentinels: 3 lists in force
```

### What the brief's List changes can and cannot see

It sees a change only once the TV asks for a name: a list that newly blocks a name the TV never asks for is invisible, which is harmless, and a list that stops blocking a tracker shows only once the TV looks it up. The row names the list by AdGuard's id (`filter_id`); `sudo grep -B1 -A3 'id: <id>' /opt/AdGuardHome/AdGuardHome.yaml` gives its name and URL. `filter_id` 0 is the custom rules (the profile's and the machine's), which have their own sections, and negative ids are AdGuard's built-in services; neither is a list change.

### Not built yet: snapshots and staged promotion

The report's next two stages are designed and held for the owner ([design decision 46](design-decisions.md#46-the-blocklists-are-watched-and-adguard-changes-only-on-purpose), owner decisions):

- **Stage A, observe.** An hourly `lists` step in the ingest reads each enabled list's file under `/opt/AdGuardHome/data/filters/<id>.txt` (rules only), hashes it, and keeps each new version gzipped under `/var/lib/tvgw/lists/<filter_id>/` (about 50 MB for 30 versions of HaGeZi Pro). It computes the effective change on the names that matter (every name the TV looked up in 30 days, their CNAME targets, the must-allow names, the clock hosts and the URL-filter hosts), not a line diff, and stores it in two new tables, `list_version` and `list_delta`, with the kinds `newly_blocked`, `newly_allowed`, `widening`, `must_allow`, `exception_added`, `modifier_added` and `volume`. It changes nothing AdGuard does. Its fixtures must be synthetic: the lists are GPL-3.0 and their text never enters the repository.
- **Stage B, promote locally.** A `tvgw-lists` timer fetches each list itself at a fixed time after the upstream's daily publication, from a pinned release, agreed by two of three mirrors, and holds a version that parses to 0 rules or shrinks by half, loses its sentinel, moves by more than a set share of rules, adds any `@@` exception or `$` modifier, widens over a protected zone, or newly blocks a name that carried content. An accepted version becomes a local file AdGuard reads (`filtering.safe_fs_patterns`, `userfilters/`), so lists go stale, never unvetted. It changes where AdGuard reads its lists, so it needs the owner's approval, two weeks in report-only mode to calibrate its thresholds, and first the namespace test that proves an empty `200` empties a list.

## What tvgw adguard apply owns

[Design decision 6](design-decisions.md#6-adguard-home-is-configured-as-code) lists the keys the plan owns. These were added on 2026-11-01, each because a UI edit or a schema bump could otherwise change what the TV gets without a trace:

| Key | Value | Why it is owned |
|---|---|---|
| `filtering.filters_update_interval` | `24` | `0` freezes every list. Owned now so a later change (Stage B wants `1`) is one reviewed line. |
| `querylog.ignored_enabled`, `statistics.ignored_enabled` | `false` | Since schema 33, names in `ignored` drop out of the query log, which is the gateway's evidence. |
| `dns.cache_enabled` | `true` | Since schema 30 the cache has its own switch; the optimistic cache below needs it on. |
| `dns.cache_optimistic` | `true` | Answers expired entries while it refreshes them: the TV keeps working while the upstreams are away ([design decision 9](design-decisions.md#9-doh-upstreams-by-ip-address)). |
| `dns.cache_optimistic_answer_ttl` | `30s` | AdGuard's default since schema 32, pinned: the TTL of such an answer. |
| `dns.cache_optimistic_max_age` | `12h` | AdGuard's default since schema 32, pinned: how long past its expiry an answer can be served. |
| `filtering.rewrites_enabled` | `true` | Since schema 31 the legacy rewrites have a switch; the plan owns the list (empty) and now its switch. |
| `filtering.blocking_mode` | `default` | Already owned; now also a tested invariant: a unit test on the plan, and the real binary in the namespace CI must answer a blocked HTTPS query with an empty NOERROR without an SOA, a blocked SVCB query with NODATA, and a blocked name with `0.0.0.0`. Never `refused`: an HTTPS query refused is a resolution failure a client may give up on. |
| `dns.fallback_dns` | empty, or `DNS_FALLBACK` | See [a fallback resolver](#a-fallback-resolver). |
| `querylog.interval`, `statistics.interval` | `QUERYLOG_DAYS`, `STATS_DAYS` days | See [what AdGuard keeps](#what-adguard-keeps). |

The duration strings are expected to be the ones AdGuard writes itself, so that a save in its UI does not read as drift. AdGuard writes durations with golibs' `timeutil.Duration`, whose `String` cuts zero units (`30s`, `12h`) and writes a whole number of days with `d` (`90d`; AdGuard reads `d` since v0.107.76). That is read from the source, not yet seen on the wire: the namespace CI's `test_adguard_keeps_the_owned_keys_as_the_plan_wrote_them` makes AdGuard save its settings (`POST /control/dns_config`), which rewrites the whole YAML, and then compares it with the plan. Until that test has passed, and on the gateway until `sudo tvgw adguard diff` stays clean after a save in the web UI, treat `90d` especially as unverified.

## The schema ceiling

`schema_version` at the top of `AdGuardHome.yaml` says which layout of keys the file uses. v0.107.79 writes 34, and AdGuard bumped it five times in eight months of 2025 and 2026; its 1.x line warns that minor releases may break compatibility. tvgw has been tested with schema 34 (`adguardcfg.SCHEMA_CEILING`). `tvgw adguard apply` refuses a file above it, before it stages anything, with the line `... is at schema_version <N>, above 34, the newest this tvgw release has been tested with; nothing changed`. The resolver keeps running as it is. `tvgw adguard diff` still reports, with a warning on stderr.

What to do: update tvgw to a release that knows the schema, or go back to the previous AdGuard Home binary together with the YAML from before it migrated. `tvgw adguard upgrade` cannot do that here: it refuses the live YAML for the same reason apply does, and the old binary's `--check-config` would reject the newer schema too. `tvgw adguard upgrade <old binary>` works only while the live schema is at or below 34. Go back by hand, with the copies an upgrade left (the binary as `AdGuardHome.bak-<stamp>-<pid>`, the YAML as `AdGuardHome.yaml.bak-<stamp>-<pid>`, the same stamp). If AdGuard updated itself, there is no such pair: install the previous release's binary and pick the newest `.bak` YAML from before the update.

```sh
sudo ls -l /opt/AdGuardHome/AdGuardHome.bak-* /opt/AdGuardHome/AdGuardHome.yaml.bak-*
sudo systemctl stop AdGuardHome
sudo cp /opt/AdGuardHome/AdGuardHome.bak-<stamp>-<pid> /opt/AdGuardHome/AdGuardHome
sudo cp /opt/AdGuardHome/AdGuardHome.yaml.bak-<stamp>-<pid> /opt/AdGuardHome/AdGuardHome.yaml
sudo systemctl start AdGuardHome
sudo tvgw adguard diff        # then sudo tvgw adguard apply if it lists drift
sudo tvgw verify
```

## Upgrading AdGuard Home

The binary changes only through `tvgw adguard upgrade NEWBIN`, because the service runs with `--no-check-update` and so never updates itself. `NEWBIN` is the `AdGuardHome` binary from a release you downloaded and checked yourself. In order, it:

1. refuses a `NEWBIN` that is not an executable file, is the installed binary itself, or reports a version below `verify.ADGUARD_MIN` (v0.107.79);
2. takes the apply lock, so no apply runs at the same time, and refuses a live YAML above the schema ceiling;
3. runs `NEWBIN --check-config` on a copy of the live YAML (a copy, because the check runs the binary's migrations), and refuses if it fails or if the copy then sits above the ceiling;
4. runs the [restart guard](#the-restart-guard);
5. runs `tvgw verify` and remembers the checks that already fail;
6. copies the live binary to `AdGuardHome.bak-<UTC stamp>-<pid>` and the YAML to `AdGuardHome.yaml.bak-...`, stops AdGuard, moves the new binary into place atomically and starts it;
7. waits up to 30 seconds for the first must-allow name to resolve, then runs `tvgw verify` again.

If the resolver does not come back, or `tvgw verify` now fails a check that passed before the swap, it stops AdGuard, puts both backups back, starts the old binary and exits 1 saying so. A check that failed before the swap (the TV switched off, say) does not stop an upgrade.

On the Pi, for the arm64 build (the release page lists each file's SHA-256 in `checksums.txt`):

```sh
cd "$(mktemp -d)"
curl -fsSLO https://github.com/AdguardTeam/AdGuardHome/releases/download/<version>/AdGuardHome_linux_arm64.tar.gz
curl -fsSL https://github.com/AdguardTeam/AdGuardHome/releases/download/<version>/checksums.txt | grep linux_arm64.tar.gz
sha256sum AdGuardHome_linux_arm64.tar.gz           # must match the line above
tar -xzf AdGuardHome_linux_arm64.tar.gz
sudo tvgw adguard upgrade "$PWD/AdGuardHome/AdGuardHome"
```

Run it while nobody depends on the TV: the swap restarts AdGuard, which empties its cache.

## The service runs with --no-check-update

AdGuard's `-s install` writes `AdGuardHome.service` with an `ExecStart` that runs the binary with `-s run` and whatever options the install was given, and its web UI offers updates that replace the binary in place, past every check above. `tvgw adguard service`, which `install.sh` runs before every apply, writes `/etc/systemd/system/AdGuardHome.service.d/20-tvgw-no-update.conf`: an empty `ExecStart=`, which clears the unit's own command (a service may have only one), then that command again with `--no-check-update`. It reads the command from the unit file systemd loaded, so a different install keeps its own arguments; a unit with no `ExecStart`, or more than one, is refused with `cannot read one ExecStart from <unit file>; add --no-check-update by hand`. It does nothing when the unit already passes the flag, or when the drop-in is already right and the running process (its `/proc/<MainPID>/cmdline`) carries the flag. A drop-in that is right while the running process lacks the flag (systemd was reloaded, but the restart never happened) gets the restart. Otherwise, holding the same lock as `apply` and `upgrade` (so the hourly re-apply cannot stop and start AdGuard in the middle), and after the restart guard, it writes the drop-in, reloads systemd, checks that `systemctl show -P ExecStart AdGuardHome` now carries the flag, restarts AdGuard and waits for a must-allow name to resolve. If any of that fails it puts the previous drop-in (or none) back and reloads systemd, and restarts AdGuard on it only if it had restarted it: a failure before the restart leaves AdGuard running as it was, with its cache. `tvgw verify`'s `adguard_pinned` check fails while the flag is missing from the unit's `ExecStart` or from the running process.

## The restart guard

Every AdGuard restart empties its cache. During an upstream outage the cache is all the TV has, because the optimistic cache keeps answering names it has seen. A restart then turns those answers into failures, and because the readiness wait cannot pass, an apply rolls back with a second restart. So before any restart, `adguardcfg.apply`, `upgrade` and `ensure_service` ask the resolver for a made-up label under the first must-allow name (`tvgw-probe-<8 hex digits>.<name>`), three tries, a new label each. The label is new each time, so neither cache can answer it: NOERROR or NXDOMAIN came from an upstream, and the guard lets the restart go ahead.

The outage that matters most fails slowly. When the upstreams drop packets instead of refusing them (the VPN tunnel down behind a drop-rule kill switch, a hung DoH connection), AdGuard waits its own `dns.upstream_timeout` (10 seconds when unset) before it answers SERVFAIL, and longer when it tries several upstreams in turn. So:

- the first try listens for that timeout plus 2 seconds (read from the live YAML, at most 32 seconds), and the other two for 1.5 seconds;
- SERVFAIL on any try, with no NOERROR or NXDOMAIN on another, means the upstreams are down;
- when no try got any answer, the guard asks for a name the profile's own rules block (`||name^`, `Desired.local_name`). AdGuard's filter answers that at once without asking an upstream. If it answers, AdGuard is alive and only its upstreams are silent: down as well;
- down raises `adguardcfg.Deferred`, whose message starts `deferred: upstream down`, before anything is staged or restarted.

AdGuard silent on the probe and on its own rule does not defer: AdGuard itself may be broken, and an apply may be the cure. A healthy guard costs one round trip; a guard that defers on a slow outage takes up to about 16 seconds with the default timeout.

The label carries nothing about the household; the upstream and the zone's own servers see a lookup of a name that cannot exist.

How each caller reports a deferral: <!-- (fin-release) -->

- `tvgw adguard apply`, `upgrade` and `service` print the line and exit 3; nothing retries them.
- `install.sh` prints `deferred: upstream down` and goes on with AdGuard as it was; the next deploy tries again.
- The analyst's autonomous block takes the rule back out of the machine's file, records an `apply` row `deferred: upstream down (block queued)` in `decisions`, and puts the block in the queue, where the next analyst run gives it its turn.
- The hourly `tvgw autoblock check` keeps its reverts, notes the deferral in each revert's reason and in an `apply` row, and exits 0; the next hourly check re-applies AdGuard, every hour until it takes. An owed re-apply that then fails for another reason (a rollback, a rejected config) stays owed and exits 1 with the same WARNING as a failed revert, as before.
- `tvgw undo` keeps the owner's revert in the file and the record, says AdGuard held its restart back, and exits 3; the next hourly check re-applies AdGuard.

## A fallback resolver

`fallback_dns` is what AdGuard asks when every upstream returns an error. Decision 6 owns it empty, so nothing is ever asked of a resolver nobody configured. `DNS_FALLBACK` names one: an encrypted resolver by IPv4 address (`https://<address>/dns-query`, `tls://<address>` or `quic://<address>`), from another operator than `DNS_UPSTREAMS`. A host name, plain DNS or one of the upstreams' own addresses is refused. It covers a provider outage, such as the 62 minutes on 2025-07-14 when both Cloudflare addresses went down together. It cannot cover a VPN tunnel outage: the fallback is AdGuard's own traffic and meets the same kill switch as the upstreams.

Setting it is an owner decision. While the upstreams fail, the fallback operator sees the TV's new lookups. The report's candidate is AdGuard DNS's non-filtering resolver by address; check its policy before you choose it. Default: empty.

## What AdGuard keeps

AdGuard keeps its own query log and statistics beside the store. The hourly ingest copies the TV's lookups into the store, so AdGuard's copy is a second record of the same lookups. `QUERYLOG_DAYS` (default 90) and `STATS_DAYS` (default 90) set `querylog.interval` and `statistics.interval`, each 1 to 365 days, AdGuard's own limits. The defaults keep what the gateway had before 2026-11-01. A shorter query log (the report proposes 72 hours and 168 hours for the statistics) is an owner decision; the retention page owns the full inventory ([privacy and retention](privacy-and-retention.md)).

## Checks on the gateway

After a deploy, on the Pi:

```sh
sudo grep -n -E 'schema_version|filters_update_interval|ignored_enabled|cache_enabled|cache_optimistic|rewrites_enabled|blocking_mode' /opt/AdGuardHome/AdGuardHome.yaml
systemctl show -P ExecStart AdGuardHome            # argv[] ends with --no-check-update
sudo tvgw adguard diff                              # AdGuard Home matches the profile and settings
sudo tvgw verify | grep -E 'adguard_|list_sentinels'
tvgw sql "select filter_id, count(*) from dns where blocked=1 group by 1"
```
