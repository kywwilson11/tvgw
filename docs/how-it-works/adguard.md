# AdGuard Home

AdGuard Home is the resolver every lookup of the TV goes through. tvgw configures it as code ([design decision 6](../design-decisions.md#6-adguard-home-is-configured-as-code)), never bundles it ([design decision 25](../design-decisions.md#25-adguard-home-is-a-checked-dependency-never-bundled)), and can install AdGuard's own release and set it up without its wizard ([design decision 52](../design-decisions.md#52-setup-fetches-adguard-homes-own-release-pinned-and-hash-checked-and-seeds-it-without-the-wizard)). This page owns what the gateway does around it: what a lookup goes through, that first run and how tvgw tells its own AdGuard from someone else's, the blocklists that change on their own and how they are watched, the keys `tvgw adguard apply` owns, the listen setting, the schema ceiling, the upgrade path, the restart guard, the optional fallback resolver, how long AdGuard keeps its own records, and how `tvgw check` asks it about one name. It is for the owner running the gateway and for anyone changing `src/tvgw/adguardcfg.py`. The decision behind it is [design decision 46](../design-decisions.md#46-the-blocklists-are-watched-and-adguard-changes-only-on-purpose).

## What a lookup goes through

Every lookup of the TV reaches AdGuard Home: the firewall's `pre_nat` chain sends DNS aimed at any server to `10.10.10.1:53`, and `tv_out` refuses DoT, DoQ and the known DoH resolvers ([the packet path](architecture.md#the-packet-path)). AdGuard answers an allowed name with its address, looked up over its DoH upstreams, and a blocked name with `0.0.0.0` (`blocking_mode` `default`, `blocked_response_ttl` 60 seconds in `src/tvgw/adguardcfg.py`); the TV's clients ask again on timers of their own, so a blocked name shows up again and again in the query log ([a day in numbers](../tv/lg-cx-measured.md#a-day-in-numbers)). With the LG profile, `tvgw adguard apply` answers the hosts of LG's file service with the gateway's address, so those downloads reach nginx's URL filter, which passes app files and refuses the ACR configuration, the telemetry schedule, LG Shopping data and promo thumbnails ([how a request reaches nginx](../../deploy/nginx/README.md#how-a-request-reaches-nginx)).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-22-lookup.dark.png">
  <img alt="A lookup from the TV meets the firewall, which sends DNS sent to any server to the filter and refuses DoT, DoQ and known DoH. The filter, AdGuard Home on the gateway, answers in one of three ways: an allowed name gets its real address and the TV goes to the internet; a blocked name gets 0.0.0.0, an answer kept 60 seconds, and leads nowhere while the TV keeps asking; with the LG profile, the names of LG's file service get the gateway's own address, so those downloads reach the URL filter, nginx, which passes app files and refuses ACR, telemetry, shopping and promo files." src="../diagrams/fig-22-lookup.light.png" width="960">
</picture>

*Every lookup of the TV ends at the filter, which answers with a real address, with `0.0.0.0`, or, for LG's file service, with the gateway's own address.*

## Installing it without the wizard

`sudo tvgw adguard install` installs AdGuard Home on a computer that has none and sets it up with no browser and nothing open to the home network (`src/tvgw/aghinstall.py`). It does nothing on a computer whose AdGuard is already tvgw's, and refuses one that serves someone else ([whose AdGuard it is](#whose-adguard-it-is)). In order, it:

1. downloads AdGuard's own release for the computer, `AdGuardHome_linux_arm64.tar.gz` or `AdGuardHome_linux_amd64.tar.gz` at the version `aghinstall.PIN` names (v0.107.79), from AdGuard's GitHub release, with the system's certificates and at most 64 MB (`MAX_DOWNLOAD`);
2. compares its SHA-256 with the hash in `aghinstall.PIN`, which is the release's own `checksums.txt` line and the digest GitHub reports for the asset; on any other hash it deletes the file and stops with `the downloaded AdGuard Home does not match tvgw's pinned hash; nothing was installed`;
3. unpacks it beside `/opt/AdGuardHome` itself, accepting only plain files and directories under `AdGuardHome/` and at most 256 MB (`MAX_UNPACKED`); a link, a device, a path outside that directory or a file named twice refuses the whole archive. The unpacked binary must report at least `verify.ADGUARD_MIN`. Then it moves the result into `/opt/AdGuardHome`;
4. starts AdGuard in a transient unit, `tvgw-adguard-firstrun`, with `--web-addr 127.0.0.1:<port>`, a free port from 20000 to 29999 chosen at random, and `--no-check-update`. With no `AdGuardHome.yaml`, AdGuard runs its first-run wizard there, on loopback only;
5. answers the wizard through AdGuard's own install API: its page on `127.0.0.1:3000`, DNS on `127.0.0.1:53`, one user, `admin`, with a random password of 32 characters, kept in `/etc/tvgw/adguard-admin` (root only). AdGuard checks both addresses first; a taken one stops the install with AdGuard's own reason before anything is configured;
6. reads the `AdGuardHome.yaml` AdGuard wrote and stops unless `users` holds exactly that one user, then logs in to the page with the password. The wizard asks for no password, so another process on the computer could have answered it first; these two checks say it did not;
7. stops the transient unit and registers AdGuard's service with its own `-s install --no-check-update`, which starts it. When AdGuard's unit already existed (its install script ran and its wizard did not), it is stopped before step 4, since it serves that wizard on AdGuard's default address, and started again here; after a failure it stays stopped;
8. writes `/var/lib/tvgw/.adguard-installed-by-tvgw` with the version, last.

If any step from 4 on fails, it stops the transient unit and any service it started, removes the YAML and the password file it wrote (never a YAML that was there before), and keeps the binary. When port 53 was the reason, it names what holds it, from `ss`. Each message and its fix is in [AdGuard install failures](../use/troubleshooting.md#adguard-install-failures). A computer whose binary is there with no YAML (AdGuard's install script ran, its wizard did not) starts at step 4; if that binary is below the floor, the pinned release replaces it first.

The YAML is then AdGuard's own, at its current schema, and `tvgw adguard apply` owns its keys from there; `install.sh` runs that apply at step 12. The apply moves DNS from `127.0.0.1` alone to `GW_IP` and `127.0.0.1` only with `ADGUARD_LISTEN=gateway`, which the template sets ([the listen setting](#the-listen-setting)). With `keep`, DNS stays where the wizard put it and the TV, whose lookups the firewall sends to `GW_IP`, gets no answer, so the install's last line says to set `gateway` first. The wizard is never used again, and `AdGuardHome.yaml` is changed only by `tvgw adguard apply` ([design decision 6](../design-decisions.md#6-adguard-home-is-configured-as-code)). To look at the page from another computer, run `sudo tvgw adguard ui` ([the AdGuard web UI](../use/maintenance.md#look-at-adguard-home)).

`install()` itself needs systemd, so it is exercised by the fakes of `tests/unit/test_aghinstall.py`; `tests/virtual/test_virtual_adguard_seed.py` runs steps 4 to 6 against the pinned binary in a namespace in CI.

## Whose AdGuard it is

`aghinstall.state()` reads what is on the computer and names one of five states:

| State | What is there | What `tvgw adguard install` does |
|---|---|---|
| `absent` | No executable `/opt/AdGuardHome/AdGuardHome` | Installs and sets it up |
| `unconfigured` | The binary, no `AdGuardHome.yaml`: its wizard never ran | Sets it up |
| `tvgw` | tvgw's marker, or a YAML that holds what `tvgw adguard apply` writes: a persistent client carrying `TV_IP` or `TV_MAC` among its ids, or every must-allow exception the profile generates in `user_rules` | Nothing |
| `old` | `tvgw`, with a binary below `verify.ADGUARD_MIN` | Refuses, naming `sudo tvgw adguard upgrade --fetch` |
| `foreign` | A YAML with none of that, or one it cannot read | Refuses |

The content decides, not the marker alone, because every gateway set up by hand before 2026-11-03 has no marker: its YAML holds the TV's client entry and the must-allow exceptions since its first apply, so it reads as `tvgw`. A `foreign` AdGuard most likely answers the household's devices: tvgw would replace its blocklists and custom rules for all of them, not only the TV. The refusal says so and leaves it alone. Running `sudo tvgw adguard apply` on it is the explicit yes that takes it over.

## Lists change on their own

The profile subscribes AdGuard to a few published blocklists (`[adguard] filters` in the profile). AdGuard re-downloads each one `filters_update_interval` hours after its last attempt, so the hour drifts, and it swaps in whatever the list's URL answers with `200 OK`. At the v0.107.79 tag its parser has no minimum rule count, so an empty `200` replaces a list with nothing, and any change of checksum counts as an update. A response other than `200` keeps the old file. Nothing in that path is reviewed: a list update is a change to what the TV may reach that no person and no watch of the gateway has looked at. Upstream mistakes happen: on 2026-09-11 HaGeZi shipped a zone-wide `nextlgsdp.com` block that broke clocks and the Content Store on webOS 6 and later, fixed about a day later.

The gateway watches that channel three ways today:

- **It owns the interval.** `tvgw adguard apply` writes `filters_update_interval: 24`, AdGuard's own default. A `0`, which AdGuard accepts since v0.107.78, would freeze every list silently; a UI edit to it is drift that the next apply puts back.
- **The sentinels.** Each HaGeZi list carries one name of its own that no other list carries. A list AdGuard has loaded answers its sentinel with `0.0.0.0`; a list that was emptied, or never loaded, answers it with an address. `tvgw verify` asks the resolver for the sentinel of every subscribed list it knows (`verify.SENTINELS`), every ten minutes.
- **List changes in the brief.** The store already records which list blocked each lookup (`dns.filter_id`). The brief's [List changes](../reference/brief-sections.md#list-changes) section names every name a list blocked for the first time in the window that the TV had resolved to an address in the 30 days before, and every name a list stopped blocking. A newly blocked name that carried content in the 14 days before its first block is a red line.

### The sentinels

| List in the profile | URL piece `verify.SENTINELS` matches | Sentinel |
|---|---|---|
| HaGeZi Pro (through AdGuard's registry) | `filter_48.txt` | `h4g3z1-pro.web.app` |
| HaGeZi LG webOS (through AdGuard's registry) | `filter_72.txt` | `h4g3z1-native-lgwebos.web.app` |
| HaGeZi DoH/VPN bypass (from jsDelivr) | `/adblock/doh.txt` | `h4g3z1-doh.web.app` |

A profile's `filters` entry may name its list's sentinel itself (`sentinel`, in [the profile format](../reference/profile-format.md#adguard)), and `tvgw verify` takes that one first; `generic-tv` names both of its lists' sentinels that way. HaGeZi publishes no document about the sentinels, so a renamed one upstream would make `list_sentinels` fail although every list is loaded. That is a loud false alarm, never an outage: check the list's file before acting. A list without a known sentinel (the Roku and Samsung native lists) is not checked.

On the gateway, the same question by hand (there is no `dig` on the gateway, so `tvgw verify` uses its own resolver code):

```sh
sudo tvgw verify | grep list_sentinels     # OK list_sentinels: 3 lists in force
```

### What the brief's List changes can and cannot see

It sees a change only once the TV asks for a name: a list that newly blocks a name the TV never asks for is invisible, which is harmless, and a list that stops blocking a tracker shows only once the TV looks it up. The row names the list by AdGuard's id (`filter_id`); `sudo grep -B1 -A3 'id: <id>' /opt/AdGuardHome/AdGuardHome.yaml` gives its name and URL. `filter_id` 0 is the custom rules (the profile's and the machine's), which have their own sections, and negative ids are AdGuard's built-in services; neither is a list change.

### Not built yet: snapshots and staged promotion

The report's next two stages are designed and held for the owner ([design decision 46](../design-decisions.md#46-the-blocklists-are-watched-and-adguard-changes-only-on-purpose), owner decisions):

- **Stage A, observe.** An hourly `lists` step in the ingest reads each enabled list's file under `/opt/AdGuardHome/data/filters/<id>.txt` (rules only), hashes it, and keeps each new version gzipped under `/var/lib/tvgw/lists/<filter_id>/` (about 50 MB for 30 versions of HaGeZi Pro). It computes the effective change on the names that matter (every name the TV looked up in 30 days, their CNAME targets, the must-allow names, the clock hosts and the URL-filter hosts), not a line diff, and stores it in two new tables, `list_version` and `list_delta`, with the kinds `newly_blocked`, `newly_allowed`, `widening`, `must_allow`, `exception_added`, `modifier_added` and `volume`. It changes nothing AdGuard does. Its fixtures must be synthetic: the lists are GPL-3.0 and their text never enters the repository.
- **Stage B, promote locally.** A `tvgw-lists` timer fetches each list itself at a fixed time after the upstream's daily publication, from a pinned release, agreed by two of three mirrors, and holds a version that parses to 0 rules or shrinks by half, loses its sentinel, moves by more than a set share of rules, adds any `@@` exception or `$` modifier, widens over a protected zone, or newly blocks a name that carried content. An accepted version becomes a local file AdGuard reads (`filtering.safe_fs_patterns`, `userfilters/`), so lists go stale, never unvetted. It changes where AdGuard reads its lists, so it needs the owner's approval, two weeks in report-only mode to calibrate its thresholds, and first the namespace test that proves an empty `200` empties a list.

## What tvgw adguard apply owns

[Design decision 6](../design-decisions.md#6-adguard-home-is-configured-as-code) lists the keys the plan owns. These were added on 2026-11-01, each because a UI edit or a schema bump could otherwise change what the TV gets without a trace:

| Key | Value | Why it is owned |
|---|---|---|
| `filtering.filters_update_interval` | `24` | `0` freezes every list. Owned now so a later change (Stage B wants `1`) is one reviewed line. |
| `querylog.ignored_enabled`, `statistics.ignored_enabled` | `false` | Since schema 33, names in `ignored` drop out of the query log, which is the gateway's evidence. |
| `dns.cache_enabled` | `true` | Since schema 30 the cache has its own switch; the optimistic cache below needs it on. |
| `dns.cache_optimistic` | `true` | Answers expired entries while it refreshes them: the TV keeps working while the upstreams are away ([design decision 9](../design-decisions.md#9-doh-upstreams-by-ip-address)). |
| `dns.cache_optimistic_answer_ttl` | `30s` | AdGuard's default since schema 32, pinned: the TTL of such an answer. |
| `dns.cache_optimistic_max_age` | `12h` | AdGuard's default since schema 32, pinned: how long past its expiry an answer can be served. |
| `filtering.rewrites_enabled` | `true` | Since schema 31 the legacy rewrites have a switch; the plan owns the list (empty) and now its switch. |
| `filtering.blocking_mode` | `default` | Already owned; now also a tested invariant: a unit test on the plan, and the real binary in the namespace CI must answer a blocked HTTPS query with an empty NOERROR without an SOA, a blocked SVCB query with NODATA, and a blocked name with `0.0.0.0`. Never `refused`: an HTTPS query refused is a resolution failure a client may give up on. |
| `dns.fallback_dns` | empty, or `DNS_FALLBACK` | See [a fallback resolver](#a-fallback-resolver). |
| `querylog.interval`, `statistics.interval` | `QUERYLOG_DAYS`, `STATS_DAYS` days | See [what AdGuard keeps](#what-adguard-keeps). |
| `dns.bind_hosts`, `dns.port` | `GW_IP` and `127.0.0.1`, port `53`, with `ADGUARD_LISTEN=gateway`; not owned with `keep` | Added 2026-11-03. See [the listen setting](#the-listen-setting). |
| `dns.ratelimit` | `0`, no limit (`adguardcfg.RATELIMIT`) | Added 2026-11-04. AdGuard's default drops a burst of the TV's lookups with no answer and no line in the query log. See [no rate limit](#no-rate-limit). |
| `dns.edns_client_subnet.enabled`, `dns.edns_client_subnet.use_custom` | `false` | Added 2026-11-04. With it on, AdGuard adds a client subnet to the lookups it sends upstream, the one in the client's query or a fixed one the web UI takes, such as the home's public address; off, a lookup tells the upstreams nothing of the home. |
| `dns.upstream_mode` | `load_balance` (`adguardcfg.UPSTREAM_MODE`) | Added 2026-11-04. Each lookup goes to one upstream, the faster more often, and to the next when it fails. `parallel` would send every lookup to every upstream, so with two operators in `DNS_UPSTREAMS` each would see all of them; `fastest_addr` would make the gateway connect to an answer's addresses to time them, traffic the TV never asked for. It is AdGuard's own default. |

The duration strings are expected to be the ones AdGuard writes itself, so that a save in its UI does not read as drift. AdGuard writes durations with golibs' `timeutil.Duration`, whose `String` cuts zero units (`30s`, `12h`) and writes a whole number of days with `d` (`90d`; AdGuard reads `d` since v0.107.76). That is read from the source, not yet seen on the wire: the namespace CI's `test_adguard_keeps_the_owned_keys_as_the_plan_wrote_them` makes AdGuard save its settings (`POST /control/dns_config`), which rewrites the whole YAML, and then compares it with the plan. Until that test has passed, and on the gateway until `sudo tvgw adguard diff` stays clean after a save in the web UI, treat `90d` especially as unverified.

### No rate limit

AdGuard Home's `dns.ratelimit` counts the UDP queries of each client subnet, a /24 for IPv4 (`ratelimit_subnet_len_ipv4`), and drops the ones over the limit in a second, 20 by default. The limiter runs before the query log, so a dropped query leaves no line there, and the brief never sees it. The TV is the only client in its /24, so a burst at power-on or when an app starts could lose lookups without a trace. AdGuard's issue calling 20 too low, opened on 2024-02-12 and closed as not planned, is open again ([#6726](https://github.com/AdguardTeam/AdGuardHome/issues/6726), read 2026-11-04).

The plan writes `0`, which AdGuard's web UI documents as no limit and its code turns into a pass-through. Two other ways were weighed:

- **`ratelimit_whitelist` with the TV's address.** At v0.107.79 and v0.107.80 AdGuard keeps the list in its YAML and shows it in the web UI, but `newRatelimitMw` builds the limiter without it, so the TV would still be limited ([`internal/dnsforward/config.go` at v0.107.79](https://github.com/AdguardTeam/AdGuardHome/blob/v0.107.79/internal/dnsforward/config.go), read 2026-11-04; AdGuard's `master` passes it).
- **A higher limit.** Any number is a guess at the TV's largest burst. The limit also never applies to TCP, so it bounds no client that means to flood the resolver. With `ADGUARD_LISTEN=gateway` AdGuard answers only on `GW_IP` and loopback, and the firewall drops any source outside the TV subnet on the TV port ([the packet path](architecture.md#the-packet-path)).

## The listen setting

`ADGUARD_LISTEN` says who decides the addresses AdGuard Home answers DNS on, `dns.bind_hosts` and `dns.port` ([the settings file](../reference/settings.md)):

- **`keep`**, the default when the key is absent. AdGuard decides: `tvgw adguard apply` leaves both keys as its wizard or its web UI set them, and `install.sh` writes AdGuard's drop-in as before. A settings file written before 2026-11-03 has no such key, so its gateway plans and starts AdGuard exactly as it did.
- **`gateway`**, which the template sets for new installs. `tvgw adguard apply` owns `dns.bind_hosts` as `GW_IP` and `127.0.0.1` and `dns.port` as `53` (`adguardcfg.listen_hosts()`). AdGuard answers the TV on the gateway's address, and the gateway's own lookups and tvgw's probes on loopback. It answers nothing else: not the home network, and not the wildcard `0.0.0.0`, which would collide with systemd-resolved's stub on `127.0.0.53`. An edit to either key in the web UI is drift: `tvgw adguard diff` reports it and the next apply puts it back.

With `gateway`, AdGuard can start only once `GW_IP` exists on the TV port. So `install.sh` step 12 writes AdGuard's drop-in with `After=network-online.target`, `Wants=network-online.target`, `Restart=always`, `RestartSec=5` and `StartLimitIntervalSec=0` ([what install.sh does](../../deploy/README.md#what-installsh-does)). A port that comes up late, such as a USB adapter, costs seconds of DNS rather than a resolver that gave up. With `keep` the drop-in holds `WorkingDirectory=/opt/AdGuardHome` alone, as it always has.

AdGuard's own documentation says systemd-resolved prevents AdGuard Home from binding to `127.0.0.1:53`, while ordinary socket rules let a specific address bind beside resolved's `127.0.0.53`. `tests/virtual/test_virtual_adguard_listen.py` checks it on CI's `ubuntu-latest`, where resolved runs: AdGuard binds `10.10.10.1` on a dummy interface and `127.0.0.1`, and must answer on both. Until that test has passed, treat `127.0.0.1` beside resolved as unverified.

Before you set `gateway` on a gateway that already runs, make sure no other device uses its AdGuard as its resolver: open the web UI ([the AdGuard web UI](../use/maintenance.md#look-at-adguard-home)) and look for clients outside `TV_NET` and `127.0.0.1` in its query log. After the change they get no answer.

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

The binary changes only through `tvgw adguard upgrade`, because the service runs with `--no-check-update` and so never updates itself. `tvgw adguard upgrade --fetch` downloads, checks and unpacks the release this tvgw pins, as steps 1 to 3 of [installing it without the wizard](#installing-it-without-the-wizard) do, into a temporary directory, and upgrades to it; when the installed binary already reports that version or a newer one, it says so and changes nothing. Where AdGuard Home is not set up, with no binary or no `AdGuardHome.yaml` beside it, it downloads nothing and names `sudo tvgw adguard install`. `tvgw adguard upgrade NEWBIN` takes the `AdGuardHome` binary from a release you downloaded and checked yourself. Either way, in order, it:

1. refuses a `NEWBIN` that is not an executable file, is the installed binary itself, or reports a version below `verify.ADGUARD_MIN` (v0.107.79);
2. takes the apply lock, so no apply runs at the same time, and refuses a live YAML above the schema ceiling;
3. runs `NEWBIN --check-config` on a copy of the live YAML (a copy, because the check runs the binary's migrations), and refuses if it fails or if the copy then sits above the ceiling;
4. runs the [restart guard](#the-restart-guard);
5. runs `tvgw verify` and remembers the checks that already fail;
6. copies the live binary to `AdGuardHome.bak-<UTC stamp>-<pid>` and the YAML to `AdGuardHome.yaml.bak-...`, stops AdGuard, moves the new binary into place atomically and starts it;
7. waits up to 30 seconds for the first must-allow name to resolve, then runs `tvgw verify` again.

If the resolver does not come back, or `tvgw verify` now fails a check that passed before the swap, it stops AdGuard, puts both backups back, starts the old binary and exits 1 saying so. A check that failed before the swap (the TV switched off, say) does not stop an upgrade.

On the gateway, for the arm64 build (the release page lists each file's SHA-256 in `checksums.txt`):

```sh
cd "$(mktemp -d)"
curl -fsSLO https://github.com/AdguardTeam/AdGuardHome/releases/download/<version>/AdGuardHome_linux_arm64.tar.gz
curl -fsSL https://github.com/AdguardTeam/AdGuardHome/releases/download/<version>/checksums.txt | grep linux_arm64.tar.gz
sha256sum AdGuardHome_linux_arm64.tar.gz           # must match the line above
tar -xzf AdGuardHome_linux_arm64.tar.gz
sudo tvgw adguard upgrade "$PWD/AdGuardHome/AdGuardHome"
```

Run it while nobody depends on the TV: the swap restarts AdGuard, which empties its cache.

## The service never updates itself

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

## Asking AdGuard Home about one name

`tvgw check NAME` asks AdGuard Home itself what it does with a name for the TV, so the verdict is the one the TV's own lookups get, from the same lists and rules, also for a name the TV has never asked for. `aghinstall.check_host()` sends `GET /control/filtering/check_host?name=NAME&client=TV_IP` to AdGuard's page on loopback, at the port `http.address` names. AdGuard answers with a reason (`FilteredBlackList`, `NotFilteredWhiteList`, `RewriteRule` and the others) and the rules that decided, each with the id of its list: `0` for the custom rules, which hold every rule tvgw plans; the `id` of an entry in `filters`; or a negative id for one of AdGuard's own features, from `-1`, the gateway's `/etc/hosts`, to `-5`, safe search ([openapi.yaml at v0.107.79](https://github.com/AdguardTeam/AdGuardHome/blob/v0.107.79/openapi/openapi.yaml), read 2026-11-04). The handler applies the TV's client settings when `client` is its address, so a rule scoped `$client=TV_IP` counts.

`src/tvgw/namecheck.py` turns that into plain words. A custom rule is named by the file `adguardcfg.rule_groups()` takes it from (the profile, `LOCAL_RULES` or `AUTO_RULES`), a list by the name the profile gives its URL. A rule in none of them is drift. The verdict, the reasons and the exit codes are in [the commands](../reference/commands.md#every-command).

AdGuard's page needs a login. tvgw sends it as HTTP basic auth, which the page takes beside its login cookie, with the user and password `tvgw adguard install` keeps in `/etc/tvgw/adguard-admin`; `aghinstall` is still the one module that reads the file. An AdGuard set up through its own first-run page has no such file. Then, at a terminal, `tvgw check` asks for the password of the YAML's user, sends it with the one request and keeps it nowhere; without a terminal it exits 2 and says so. To skip the question, write the file once, on the gateway:

```sh
sudo install -m 600 /dev/null /etc/tvgw/adguard-admin
sudoedit /etc/tvgw/adguard-admin      # two lines: user=<name> and password=<password>
```

AdGuard counts a refused password against logins from the same address: after `auth_attempts` refusals (5 by default) it takes none for `block_auth_min` minutes (15), its defaults in `internal/home/config.go` at the tag.

The answer's shape is read from the openapi file and from the handler at the tag (`internal/filtering/http.go`), and the unit tests answer the same way from a stand-in. The namespace CI's `test_check_host_names_the_rule_tvgw_check_reads` asks the real binary for a blocked, a must-allow and a URL-filter name; until that test has passed, treat the shape as unverified. A `$dnsrewrite` answer carries no addresses, so the URL filter's names are told by their rule, never by `ip_addrs`.

## Checks on the gateway

After a deploy, on the gateway:

```sh
sudo grep -n -E 'schema_version|filters_update_interval|ignored_enabled|cache_enabled|cache_optimistic|rewrites_enabled|blocking_mode|ratelimit:|upstream_mode' /opt/AdGuardHome/AdGuardHome.yaml
sudo grep -n -A3 'edns_client_subnet:' /opt/AdGuardHome/AdGuardHome.yaml   # enabled: false, use_custom: false
systemctl show -P ExecStart AdGuardHome            # argv[] ends with --no-check-update
sudo tvgw adguard diff                              # AdGuard Home matches the profile and settings
sudo tvgw verify | grep -E 'adguard_|list_sentinels'
tvgw sql "select filter_id, count(*) from dns where blocked=1 group by 1"
```
