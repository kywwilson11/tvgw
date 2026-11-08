# AdGuard Home

AdGuard Home is the resolver every lookup of the TV goes through. tvgw configures it as code ([design decision 6](../design-decisions.md#6-adguard-home-is-configured-as-code)), never bundles it ([design decision 25](../design-decisions.md#25-adguard-home-is-a-checked-dependency-never-bundled)), and can install AdGuard's own release and set it up without its wizard ([design decision 52](../design-decisions.md#52-setup-fetches-adguard-homes-own-release-pinned-and-hash-checked-and-seeds-it-without-the-wizard)). This page owns what the gateway does around it: what a lookup goes through, that first run and how tvgw tells its own AdGuard from someone else's, the blocklists that change on their own and how they are watched, the keys `tvgw adguard apply` owns, the listen setting, the schema ceiling, the upgrade path, the restart guard, (resolver) who answers the lookups and how that changes, the optional fallback resolver, how long AdGuard keeps its own records, how `tvgw check` asks it about one name, and how `tvgw refused` reads what it just refused the TV. It is for the owner running the gateway and for anyone changing `src/tvgw/adguardcfg.py`. The decision behind it is [design decision 46](../design-decisions.md#46-the-blocklists-are-watched-and-adguard-changes-only-on-purpose).

## What a lookup goes through

Every lookup of the TV reaches AdGuard Home: the firewall's `pre_nat` chain sends DNS aimed at any server to `10.10.10.1:53`, and `tv_out` refuses DoT, DoQ and the known DoH resolvers ([the packet path](architecture.md#the-packet-path)). AdGuard answers an allowed name with its address, looked up over its DoH upstreams, and a blocked name with `0.0.0.0` (`blocking_mode` `default`, `blocked_response_ttl` 60 seconds in `src/tvgw/adguardcfg.py`); the TV's clients ask again on timers of their own, so a blocked name shows up again and again in the query log ([a day in numbers](../tv/lg-cx-measured.md#a-day-in-numbers)). With the LG profile, `tvgw adguard apply` answers the hosts of LG's file service with the gateway's address, so those downloads reach nginx's URL filter, which passes app files and refuses the ACR configuration, the telemetry schedule, LG Shopping data and promo thumbnails ([how a request reaches nginx](../../deploy/nginx/README.md#how-a-request-reaches-nginx)).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../diagrams/fig-22-lookup.dark.png">
  <img alt="A lookup from the TV meets the firewall, which sends DNS sent to any server to the filter and refuses DoT, DoQ and known DoH. The filter, AdGuard Home on the gateway, answers in one of three ways: an allowed name gets its real address and the TV goes to the internet; a blocked name gets 0.0.0.0, an answer kept 60 seconds, and leads nowhere while the TV keeps asking; with the LG profile, the names of LG's file service get the gateway's own address, so those downloads reach the URL filter, nginx, which passes app files and refuses ACR, telemetry, shopping and promo files." src="../diagrams/fig-22-lookup.light.png" width="960">
</picture>

*Every lookup of the TV ends at the filter, which answers with a real address, with `0.0.0.0`, or, for LG's file service, with the gateway's own address.*

## Installing it without the wizard

`sudo tvgw adguard install` installs AdGuard Home on a computer that has none and sets it up with no browser and nothing open to the home network (`src/tvgw/aghinstall.py`). It does nothing on a computer whose AdGuard is already tvgw's, and refuses one that serves someone else ([whose AdGuard it is](#whose-adguard-it-is)). In order, it:

1. downloads AdGuard's own release for the computer, `AdGuardHome_linux_arm64.tar.gz` or `AdGuardHome_linux_amd64.tar.gz` at the version `aghinstall.PIN` names (v0.107.80), from AdGuard's GitHub release, with the system's certificates and at most 64 MB (`MAX_DOWNLOAD`);
2. compares its SHA-256 with the hash in `aghinstall.PIN`, which is the release's own `checksums.txt` line and the digest GitHub reports for the asset; on any other hash it deletes the file and stops with `the downloaded AdGuard Home does not match tvgw's pinned hash; nothing was installed`;
3. unpacks it beside `/opt/AdGuardHome` itself, accepting only plain files and directories under `AdGuardHome/` and at most 256 MB (`MAX_UNPACKED`); a link, a device, a path outside that directory or a file named twice refuses the whole archive. The unpacked binary must report at least `verify.ADGUARD_MIN`. Then it moves the result into `/opt/AdGuardHome`;
4. starts AdGuard in a transient unit, `tvgw-adguard-firstrun`, with `--web-addr 127.0.0.1:<port>`, a free port from 20000 to 29999 chosen at random, and `--no-check-update`. With no `AdGuardHome.yaml`, AdGuard runs its first-run wizard there, on loopback only;
5. answers the wizard through AdGuard's own install API: its page on `127.0.0.1:3000`, DNS on `127.0.0.1:53`, one user, `admin`, with a random password of 32 characters, kept in `/etc/tvgw/adguard-admin` (root only). AdGuard checks both addresses first; a taken one stops the install with AdGuard's own reason before anything is configured;
6. reads the `AdGuardHome.yaml` AdGuard wrote and stops unless `users` holds exactly that one user, then logs in to the page with the password. The wizard asks for no password, so another process on the computer could have answered it first; these two checks say it did not;
7. stops the transient unit and registers AdGuard's service with its own `-s install --no-check-update`, which starts it. When AdGuard's unit already existed (its own `-s install` or install script ran, and its wizard did not), it is stopped before step 4, since it serves that wizard on AdGuard's default address, and started again here; after a failure it stays stopped;
8. writes `/var/lib/tvgw/.adguard-installed-by-tvgw` with the version, last.

If any step from 4 on fails, it stops the transient unit and any service it started, removes the YAML and the password file it wrote (never a YAML that was there before), and keeps the binary. When port 53 was the reason, it names what holds it, from `ss`. Each message and its fix is in [AdGuard install failures](../use/troubleshooting.md#adguard-install-failures). A computer whose binary is there with no YAML (its release was unpacked or its install script ran, and its wizard did not) starts at step 4; if that binary is below the floor, the pinned release replaces it first.

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

The content decides, not the marker alone, because every gateway set up by hand before 2026-11-03 has no marker: its YAML holds the TV's client entry and the must-allow exceptions since its first apply, so it reads as `tvgw`. A `foreign` AdGuard may answer the household's devices: tvgw would replace its blocklists and custom rules for all of them, not only the TV. The refusal says so and leaves it alone.

### Taking over one that is not tvgw's

`tvgw adguard apply` moves AdGuard's page to `127.0.0.1:3000`, replaces its custom rules, its upstreams and its allowlists, and with `ADGUARD_LISTEN=gateway` moves its DNS to `GW_IP` and `127.0.0.1` ([what tvgw adguard apply owns](#what-tvgw-adguard-apply-owns)). `install.sh` runs that apply at step 12, so the package's postinst and setup's apply pass do too. On an AdGuard Home that the house uses as its resolver, every other device would lose its DNS and the owner the page, while `tvgw verify`, which looks at the TV, says OK. So since 2026-11-04 the apply looks at an AdGuard Home whose state is `foreign` for what says it serves more than the TV and this computer (`aghinstall.takeover_evidence()`), and goes by how strong that is (`aghinstall.refused()`):

| What it finds | Evidence | `ADGUARD_TAKE_OVER=ask`, the default | `no` | `yes` |
|---|---|---|---|---|
| Its query log answered a client outside `TV_NET` and loopback in the last 7 days (`OTHERS_DAYS`) | strong: it serves the house | refused; setup asks, yes by default | refused | taken over |
| No such client (an empty or absent log included), and it answers DNS beyond `GW_IP` and loopback: `dns.bind_hosts` missing or empty, `0.0.0.0` or `::` (every address, the wizard's usual answer), another address, or a YAML it cannot read | weak: it could serve the house, and nobody else asked it | taken over, with one line; setup asks, no by default | refused | taken over |
| No such client, and it listens on `GW_IP` and loopback alone | none | taken over, silently | taken over | taken over |

The log is read backwards from the end of `querylog.json` (in `querylog.dir_path` when the YAML names one), then of its rotated copy `querylog.json.1`, at most 16 MB of each (`adguard.CLIENTS_MAX_BYTES`), and the read stops at the first record older than the window (`adguard.clients_since()`). Where it listens is `aghinstall.listens_beyond()`.

A refusal names what it found, up to three clients newest first, says what a take-over would do, and changes nothing; the apply exits 4. `install.sh` then stops with 77 and one line: set `ADGUARD_TAKE_OVER=yes` in `/etc/tvgw/tvgw.conf` and run the install again (`sudo dpkg --configure -a` under the postinst), or put tvgw on a computer of its own. A take-over on the weak evidence alone prints `tvgw adguard: AdGuard Home listens on every address of this computer but served no other device in the last 7 days: tvgw takes it over; set ADGUARD_TAKE_OVER=no to refuse`, and the install goes on. That is the first install the install guide describes, whose wizard step answers every interface a few minutes before tvgw arrives. `tvgw adguard diff` and `apply --dry-run` say what the apply would do. `tvgw allow`, `tvgw block` and the autonomy's reverts apply through the same check.

`tvgw setup` asks before it writes anything, whenever there is evidence and the setting is `ask`: `Does anything else in the house use this AdGuard Home?`, with what it found. On the strong evidence yes is the default, and stops setup with nothing written; no writes `ADGUARD_TAKE_OVER=yes`. On the weak evidence no is the default, and the apply takes it over; yes stops setup. An unattended run takes the default, so it stops on the strong evidence unless its answers file sets `ADGUARD_TAKE_OVER=yes`, and goes on, saying so, on the weak. With `ADGUARD_TAKE_OVER=no` setup stops without a question.

An AdGuard Home that is tvgw's (its marker, or its content as above) is never checked, so the owner's gateway, which listens on `0.0.0.0` under `keep`, applies as it always did. `tvgw adguard apply --take-over` is `yes` for one run ([the settings file](../reference/settings.md)). The check does not see a device whose lookups AdGuard keeps out of its log (`ignore_querylog` on a client, or the log switched off): on the weak evidence such an AdGuard Home is taken over under `ask`, so on a computer whose AdGuard Home serves the house with its log off, set `no`.

## Lists change on their own

The profile subscribes AdGuard to a few published blocklists (`[adguard] filters` in the profile). AdGuard re-downloads each one `filters_update_interval` hours after its last attempt, so the hour drifts, and it swaps in whatever the list's URL answers with `200 OK`. At the v0.107.79 tag its parser has no minimum rule count, so an empty `200` replaces a list with nothing, and any change of checksum counts as an update. A response other than `200` keeps the old file. Nothing in that path is reviewed: a list update is a change to what the TV may reach that no person and no watch of the gateway has looked at. Upstream mistakes happen: on 2026-09-11 HaGeZi shipped a zone-wide `nextlgsdp.com` block that broke clocks and the Content Store on webOS 6 and later, fixed about a day later.

The gateway watches that channel four ways today, and (listguard) holds the profile's red-line blocks against it ([the list guard](#the-list-guard)):

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

It sees a change only once the TV asks for a name: a list that newly blocks a name the TV never asks for is invisible, which is harmless, and a list that stops blocking a tracker shows only once the TV looks it up. The row names the list by AdGuard's id (`filter_id`); `sudo grep -B1 -A3 'id: <id>' /opt/AdGuardHome/AdGuardHome.yaml` gives its name and URL. (rule use) `sudo tvgw lists` names each list beside what it refused ([what each rule and list did](#what-each-rule-and-list-did)). `filter_id` 0 is the custom rules (the profile's and the machine's), which have their own sections, and negative ids are AdGuard's built-in services; neither is a list change.

### The list guard

(listguard) A list can do more than block. In AdGuard's precedence, urlfilter's `IsHigherPriority`, an exception carrying `$important` outranks everything, then a block carrying it, then a plain exception, then a plain block, whichever list or custom rule each sits in and in whatever order. So a plain `@@` line in any subscribed list lifts every plain block of the same name, and a `$badfilter` line deletes the rule it names from every source ([design decision 68](../design-decisions.md#68-a-lists-plain-exception-no-longer-lifts-the-profiles-red-line-blocks-the-lists-are-scanned-for-lines-that-act-on-the-tvs-rules-each-update-is-previewed-against-the-tvs-lookups-and-a-doh-list-refresh-that-drops-more-than-a-set-share-is-held-back)). Three things follow from that:

- **Held blocks.** The profile loads each block of its `.rules` file whose name it files under a red-line category with `$important` (`profile.held_rule`): content recognition, and the vendor's own advertising, usage reporting and fingerprinting ([the profile format](../reference/profile-format.md#the-rules-file)). A list's plain exception no longer lifts them; the owner's `tvgw allow`, which carries `$important` too, still does. Third-party trackers, voice, the IoT links and the declutter blocks stay plain, and a list can lift them.
- **The scan.** The hourly ingest's `lists` step, `listguard.run`, reads every enabled list of the YAML from the file AdGuard keeps it in, `/opt/AdGuardHome/data/filters/<id>.txt`, and fetches nothing. It runs when a list's file or the TV's rules changed, and once a day otherwise (`SCAN_EVERY`). It names every line that acts on one of the TV's own rules, the profile's or the owner's: one that lifts a block, one a held block holds off, and one that would let a list refuse a must-allow name or undo the URL filter, among them a list's own `$dnsrewrite` of a URL-filter name, which answers before any exception. An exception is judged on the A, HTTPS and SVCB lookups it is for (AAAA is answered empty for every client), against what the TV's own rules answer each name today, so a name the owner's allow already lets through is no finding. A list's block of a must-allow name is no finding, since the exception outranks it, and the machine's rules are left out. The rule that withholds HTTPS and SVCB records from the TV is not judged: a list's plain exception for a name lifts it for that name. The brief's [List guard](../reference/brief-sections.md#list-guard) lists them; a line that lifts a block or could refuse a name the TV needs is a red line on the day it appears. `tvgw lists` prints the last scan, and `sudo tvgw lists --scan` scans now.
- **The preview.** The step keeps a gzipped copy of each list's rule lines under `/var/lib/tvgw/lists/`. When a list's file changed since that copy, it judges every public name the TV looked up in the 14 days before against the list as it was and as it is, with every other rule as it stands, and the brief's [List update preview](../reference/brief-sections.md#list-update-preview) names each verdict that changed. AdGuard swaps a list in as it downloads it, so the preview comes at the first hourly ingest after the change, not before.

The rules both read through `listguard.Engine`, a model of AdGuard's precedence for the forms tvgw and the lists use: `||name^`, other adblock patterns, `/regex/`, hosts-file lines, and the modifiers `$important`, `$badfilter`, `$dnsrewrite`, `$dnstype`, `$client`, `$ctag` and `$denyallow`. AdGuard drops a rule with any other modifier, and so does the model; the scan counts such lines per list (`unread` in `tvgw lists`). The scan judges an exception written as a regex, or without anchors, on the blocked name and one name under it, and a regex block on names filled from the profile's categories; neither the scan nor the preview follows CNAME targets. The namespace CI asks the pinned binary, with a list file of the test's own, about a held block under a list's plain exception and under a `$badfilter` of its unheld form, two held regex blocks, one under a list's exception, a plain block a list's exception lifts, a must-allow name under a list's `$important` block, the URL filter's rewrite under a list's plain exception, and a control the list alone blocks; the model must agree on each. No other case is checked against the binary.

On the gateway:

```sh
tvgw lists                     # the lists, every line that acts on the TV's rules, then what each refused
sudo tvgw lists --scan         # scan now rather than at the next change
```

### Not built yet: snapshots and staged promotion

The report's next two stages are designed and held for the owner ([design decision 46](../design-decisions.md#46-the-blocklists-are-watched-and-adguard-changes-only-on-purpose), owner decisions). (listguard) Part of Stage A is built since 2026-11-08 as [the list guard](#the-list-guard): one copy of each list rather than thirty versions, and the effective change on the names the TV looked up in 14 days, kept in `meta` rather than in two tables.

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

Before you set `gateway` on a gateway that already runs, make sure no other device uses its AdGuard as its resolver: open the web UI ([the AdGuard web UI](../use/maintenance.md#look-at-adguard-home)) and look for clients outside `TV_NET` and `127.0.0.1` in its query log. After the change they get no answer. On an AdGuard Home that is not tvgw's, the apply makes that check itself ([taking over one that is not tvgw's](#taking-over-one-that-is-not-tvgws)); on tvgw's own it does not, since the TV's client entry already says tvgw set it up.

## The schema ceiling

`schema_version` at the top of `AdGuardHome.yaml` says which layout of keys the file uses. v0.107.79 and v0.107.80 write 34 (`configmigrate.LastSchemaVersion` at each tag, read 2026-11-05), and AdGuard bumped it five times in eight months of 2025 and 2026; its 1.x line warns that minor releases may break compatibility. tvgw has been tested with schema 34 (`adguardcfg.SCHEMA_CEILING`). `tvgw adguard apply` refuses a file above it, before it stages anything, with the line `... is at schema_version <N>, above 34, the newest this tvgw release has been tested with; nothing changed`. The resolver keeps running as it is. `tvgw adguard diff` still reports, with a warning on stderr.

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

To go back to the release before an upgrade, hand the copy it left to the same command, `sudo tvgw adguard upgrade /opt/AdGuardHome/AdGuardHome.bak-<stamp>-<pid>`: the old binary goes through the same checks and the same swap, and the upgrade leaves a copy of the newer one. That works while the live YAML is at a schema the old binary reads, as it is between v0.107.79 and v0.107.80, which both write 34; past a schema bump, go back by hand as [the schema ceiling](#the-schema-ceiling) says.

### The 1.0 betas against the pin

(reliability) tvgw pins v0.107.80 (`aghinstall.PIN`) and moves to no beta. AdGuard's releases page, read 2026-11-08, lists two of the 1.0 line ([releases](https://github.com/AdguardTeam/AdGuardHome/releases)): v1.0.0-b.1 (30 Sep), which "switched" the beta channel "to the new UI and versioning scheme" and fixed "reading partially received TCP prefix", and v1.0.0-b.2 (5 Nov), which fixed an "invalid SVCB record from DDR when DoH routes are empty". Before a stable 1.0 is pinned, check on a copy, as `tvgw adguard upgrade` does: its `schema_version` against [the schema ceiling](#the-schema-ceiling); whether the TCP prefix fix moves the in-path filler's `unparsed_tcp` count; and its answer to `_dns.resolver.arpa`, the owed test T8, now that the DDR fix is in ([design decision 73](../design-decisions.md#73-the-store-refuses-a-newer-version-and-commits-durably-the-gateway-samples-its-own-health-the-quic-refusal-is-watched-an-encrypted-copy-leaves-the-box)).

## The service never updates itself

AdGuard's `-s install` writes `AdGuardHome.service` with an `ExecStart` that runs the binary with `-s run` and whatever options the install was given, and its web UI offers updates that replace the binary in place, past every check above. `tvgw adguard service`, which `install.sh` runs before every apply, writes `/etc/systemd/system/AdGuardHome.service.d/20-tvgw-no-update.conf`: an empty `ExecStart=`, which clears the unit's own command (a service may have only one), then that command again with `--no-check-update`. It reads the command from the unit file systemd loaded, so a different install keeps its own arguments; a unit with no `ExecStart`, or more than one, is refused with `cannot read one ExecStart from <unit file>; add --no-check-update by hand`. It does nothing when the unit already passes the flag, or when the drop-in is already right and the running process (its `/proc/<MainPID>/cmdline`) carries the flag. A drop-in that is right while the running process lacks the flag (systemd was reloaded, but the restart never happened) gets the restart. Otherwise, holding the same lock as `apply` and `upgrade` (so the hourly re-apply cannot stop and start AdGuard in the middle), and after the restart guard, it writes the drop-in, reloads systemd, checks that `systemctl show -P ExecStart AdGuardHome` now carries the flag, restarts AdGuard and waits for a must-allow name to resolve. If any of that fails it puts the previous drop-in (or none) back and reloads systemd, and restarts AdGuard on it only if it had restarted it: a failure before the restart leaves AdGuard running as it was, with its cache. `tvgw verify`'s `adguard_pinned` check fails while the flag is missing from the unit's `ExecStart` or from the running process.

## The restart guard

Every AdGuard restart empties its cache. During an upstream outage the cache is all the TV has, because the optimistic cache keeps answering names it has seen. A restart then turns those answers into failures, and because the readiness wait cannot pass, an apply rolls back with a second restart. So before any restart, `adguardcfg.apply`, `upgrade` and `ensure_service` ask the resolver for a made-up label under the first must-allow name (`tvgw-probe-<8 hex digits>.<name>`), three tries, a new label each. The label is new each time, so neither cache can answer it: NOERROR or NXDOMAIN came from an upstream, and the guard lets the restart go ahead.

The outage that matters most fails slowly. When the upstreams drop packets instead of refusing them (the VPN tunnel down behind a drop-rule kill switch, a hung DoH connection), AdGuard waits its own `dns.upstream_timeout` (10 seconds when unset) before it answers SERVFAIL, and longer when it tries several upstreams in turn. So:

- the first try listens for that timeout plus 2 seconds (read from the live YAML, at most 32 seconds), and the other two for 1.5 seconds;
- SERVFAIL on any try, with no NOERROR or NXDOMAIN on another, means the upstreams are down;
- when no try got any answer, the guard asks for a name the profile's own rules block (`||name^`, `Desired.local_name`). AdGuard's filter answers that at once without asking an upstream. If it answers, AdGuard is alive and only its upstreams are silent: down as well;
- down raises `adguardcfg.Deferred`, whose message starts `deferred: upstream down`, before anything is staged or restarted.

AdGuard silent on the probe and on its own rule does not defer: AdGuard itself may be broken, and an apply may be the cure. (resolver) Nor does `apply` hold back when the upstreams AdGuard asks are not the ones the plan names (a resolver change cut short, a hand edit of `DNS_UPSTREAMS`) and every planned upstream answers a direct DoH test from the gateway at that moment: the guard keeps a working config's cache, not a broken one, so the apply goes on, says so on stderr, and keeps its readiness wait and restore. The two lists are compared as sets after `same_upstreams` normalizes them (order, a scheme's default port, a trailing slash and `#` comment lines do not count), and an upstream the test cannot ask (a host name, `tls://`) counts as not answering. In an outage of the internet or the tunnel the planned upstreams do not answer either, and the deferral holds. A healthy guard costs one round trip; a guard that defers on a slow outage takes up to about 16 seconds with the default timeout.

The label carries nothing about the household; the upstream and the zone's own servers see a lookup of a name that cannot exist.

How each caller reports a deferral: <!-- (fin-release) -->

- `tvgw adguard apply`, `upgrade` and `service` print the line and exit 3; nothing retries them.
- `install.sh` prints `deferred: upstream down` and goes on with AdGuard as it was; the next deploy tries again.
- The analyst's autonomous block takes the rule back out of the machine's file, records an `apply` row `deferred: upstream down (block queued)` in `decisions`, and puts the block in the queue, where the next analyst run gives it its turn.
- The hourly `tvgw autoblock check` keeps its reverts, notes the deferral in each revert's reason and in an `apply` row, and exits 0; the next hourly check re-applies AdGuard, every hour until it takes. An owed re-apply that then fails for another reason (a rollback, a rejected config) stays owed and exits 1 with the same WARNING as a failed revert, as before.
- `tvgw undo` keeps the owner's revert in the file and the record, says AdGuard held its restart back, and exits 3; the next hourly check re-applies AdGuard.

## Who answers the lookups

AdGuard Home sends each lookup it does not answer itself to one of the upstreams `DNS_UPSTREAMS` names, DoH URLs by IPv4 address ([design decision 9](../design-decisions.md#9-doh-upstreams-by-ip-address)); that operator sees every name the filter lets through. (resolver) `tvgw resolver` makes it a plain choice ([design decision 81](../design-decisions.md#81-who-answers-the-tvs-lookups-is-the-owners-choice-among-checked-operators-that-do-not-filter-changed-all-or-nothing)). `resolver.PRESETS` in `src/tvgw/resolver.py` holds the operators offered: none filters, none needs an account, each is DoH by address with a certificate valid for the address, and its bootstrap is the same operator's addresses. A candidate not yet seen to answer so (`checked` empty) is offered nowhere; `tvgw resolver test NAME` asks it from the gateway.

`sudo tvgw resolver set NAME` changes it all or nothing. It takes the install lock and the autonomy's lock, then reads the settings, the profile and AdGuard Home's own `dns.upstream_dns` again, so a change it waited for counts; "already answers" means the settings and AdGuard both say so. While it runs, SIGHUP (a dropped SSH session) and SIGTERM raise as Ctrl-C does, so the way back in step 5 runs before the process ends:

1. It asks each new address directly, over DoH with the certificate held to the address, for a made-up name under the profile's first must-allow host (`resolver.precheck`). One that does not answer refuses the change with nothing written.
2. It writes `DNS_UPSTREAMS`, and for a preset `DNS_BOOTSTRAP`, with `config.save_conf`, which refuses a file the next command could not load. When the settings already name the target and only AdGuard differs, nothing is written and the next step is a repair.
3. It applies AdGuard Home as `tvgw allow` does (`analyst.adguardcfg_apply`), behind [the restart guard](#the-restart-guard). With the current upstreams down it goes past the guard only when the new ones answer a direct test at that moment; otherwise it exits 3 with the settings file put back byte for byte.
4. It asks the guard's own probe at `GW_IP`, where the TV asks, which must come back `up`, then every must-allow name (`verify.must_allow_check`, with its one retry), then each new address directly once more.
5. On any failure from step 2 on, an interrupt or a test that cannot run included, it writes the old settings file back byte for byte (compared and written as bytes) and applies AdGuard Home again from it with a guard that never defers: the guard would see the failed new upstreams and hold the TV on them, and the restart has already emptied the cache. Ctrl-C, SIGHUP and SIGTERM wait until this is done.
6. A change that took is one `resolver_change` line in the change ledger, class A, naming the preset or `custom`.

`set custom URL[,URL]` takes the owner's own operator: DoH by IPv4 address only, never a loopback, link-local, multicast or reserved address, nor `GW_IP`. It leaves `DNS_BOOTSTRAP` as it is, since AdGuard asks the bootstrap only to look up an upstream given by name ([AdGuard Home's configuration](https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration), read 2026-11-08). With `DNS_FALLBACK` set, the probe and the must-allow names in step 4 cannot tell the new operator from the fallback; the direct asks in steps 1 and 4 are what show the new one answers. A DoH answer counts only as a DNS message answering the question asked. `tvgw resolver show` says who answers now and, run as root, whether AdGuard Home's own `dns.upstream_dns` differs from the settings. When they differ, `sudo tvgw adguard apply` brings AdGuard to the settings, past a deferral once their operator answers ([the restart guard](#the-restart-guard)).

`tvgw setup` asks the same question, tests a new choice from the gateway, and makes the change this way once the installer has run, never by writing it with the other settings.

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

## What the TV was just refused

`sudo tvgw refused` answers the question an app that stopped working asks: which name was it refused, just now. The store cannot answer it, because the hourly ingest copies the query log into it up to an hour late, and AdGuard itself writes the log in batches of `querylog.size_memory` lookups (10, `log_buffer` in src/tvgw/adguardcfg.py), so the file can lag the TV by minutes when it asks for little. `src/tvgw/refused.py` reads AdGuard's own log two ways, and either is enough:

| Read | How | What it gives |
|---|---|---|
| The file | `adguard.records_since()` reads `querylog.json` back from its end, then its rotated copy `querylog.json.1`, at most `CLIENTS_MAX_BYTES` (16 MB) of each, the TV's lines alone, from the store's newest lookup on, so the log covers the hours the store does not hold yet. | Everything AdGuard has written, and the lookups between the last ingest and the window, for "before" |
| The page | `aghinstall.querylog()` sends `GET /control/querylog?limit=500&search="TV_IP"`, with the address in double quotes, which AdGuard matches whole against the client, up to `API_PAGES` (4) pages back through `older_than`, with the user and password `tvgw check` uses. | The newest lookups, those AdGuard still holds in memory among them |

A lookup in both counts once: the two records of one lookup carry the same time to the nanosecond, name and type (`refused._key()`). A page's `oldest` decides how far the read goes (`refused.api_records()`): it is the oldest entry on the page, or, on a page with none, where AdGuard's scan of its file stopped, which it caps at 50,000 lines a request; it is empty once AdGuard has nothing older. An empty `oldest` ends the read, an `oldest` before the window's start completes it, and any other is followed with `older_than` set to it, an empty page included. When the page cannot be asked, the report comes from the file and says so, with the remedy first: with no password kept and no terminal, to run it at a terminal or keep the password in `/etc/tvgw/adguard-admin`, never on a command line; when AdGuard did not answer, to run it again in a minute. When the file cannot be read either, it exits 2 with one line. The shape of the page is read from `internal/querylog/http.go`, `json.go` and `searchcriterion.go` at v0.107.79 ([AdGuard Home at v0.107.79](https://github.com/AdguardTeam/AdGuardHome/tree/v0.107.79/internal/querylog), read 2026-11-05). The namespace CI's `test_the_query_log_page_and_file_give_tvgw_refused_the_same_lookups` asks the real binary for both; until that test has passed, treat the shape as unverified.

Each refused name is then ranked, the likeliest cause of a broken app first:

1. A name the profile says the TV needs: a must-allow host, a name the URL filter answers, or a name that matches a `clock_hosts` pattern. A must-allow name refused at all contradicts the plan, and its fix is `sudo tvgw doctor`.
2. A refusal the record has not seen: first sight. A refusal is old news when the same rule refused the name itself, or another name under the same registrable domain (or, under `NAME_HMAC=on`, title zone), before, unless the filter let the name through after its last refusal: then whatever refused it had stopped, a list's rule taken out and put back or another rule, and the refusal is new. Lookups of the record types the TV goes without count neither as refusals nor as let through. So a rotating name such as `cdpbeacon9.lgtvcommon.com` under a rule that has refused the domain for a month is no first sight. The domain's other names come from `hosts`, the most recently seen 200 (`DOMAIN_NAMES`) whatever their last verdict, title tags included, each then asked by the `(qname, t)` index (`refused.domain_history()`). One the filter let through before ranks ahead of one the TV never asked for, since the first is something that changed and the second a new feature. "Before" is the store, opened read-only (`mode=ro`), and the log between the store's newest lookup and the window. With no store, the log alone, and a note under the first line says how far back that reaches; a log read that stops short of the store's newest lookup says so there too, and `history_complete` is false in the JSON. The reason a name is first never claims more than that: it says "not in the record since" the day the record starts.
3. Then the most retried: the refused lookups in the window.

A known tracker (`plain.is_tracking()`: ACR, ads, telemetry, fingerprinting) ranks below every other name, and is never on its own the likely cause or a reason to exit 1, since an app rarely stops for want of an ad host; a tracker the TV never asked for before is said to be new, refused on purpose.

For a likely cause the report gives `tvgw check`'s words: the rule and where it comes from (`namecheck.source()`), the category, the company where the snapshot knows one, and the fix (`namecheck.fix()`). Every other name gets one line and no fix: whether it is refused on purpose (a tracking category, or a rule of the profile or a list it subscribes to), and so unlikely to break an app, or by the owner's or the gateway's own rule, its category and its company, then one closing line that names `sudo tvgw check <name>`, where the allow is for whoever means it. A privacy gateway does not hand out an unblock for every tracker it refuses; `--all` prints every rule and fix. Lookups of `AAAA`, `HTTPS` and `SVCB` records (`HARMLESS_QTYPES` in src/tvgw/profile.py) are left out: the profile withholds the last two on purpose, and the TV goes without all three. A name that is not an internet name (`names.is_public_name()`: the home network's own names, reverse lookups, addresses, a name with a control or invisible character) is counted in a note and never printed, nor is another device's lookup or anything of AdGuard's client record. With `NAME_HMAC=on`, a name under a title zone is shown as `<title>.<zone>`, one row for every title under the zone, since the store keeps those names only as keyed tags.

A query-log answer that cannot be read is reported by its size alone (`not JSON (N bytes)`), never by its first characters, which would hold the TV's address. The report writes nothing: no store, no key of the name hasher, no file. Its exit codes and options are in [the commands](../reference/commands.md#every-command).

(ports) It also reads what the firewall itself refused, which AdGuard Home never sees ([design decision 71](../design-decisions.md#71-the-port-walls-are-ready-to-switch-the-probe-checks-them-and-tvgw-refused-reads-the-firewall)): the counters of the firewall's refusing rules, from the store's newest counter snapshot at or before the window to now (so a count may reach back up to ten minutes, and its line says from when), and the samples its rules write to the kernel log, which name an unusual port's or a clock server's address. The clock port, once it is narrowed, ranks first, as a name the TV needs does; an unusual port refused by `STRICT_PORTS=yes`, an address on your own block list, or an address the gate refused, when the record has not seen it refused before; QUIC, encrypted lookups around the filter, the home network, LG's advertising ports and the other walls kept on purpose come after every name and are never the likely cause.

## What each rule and list did

`tvgw rules --local` and the last section of `tvgw lists`, after [the list guard](#the-list-guard)'s findings, answer from the store what the owner's rules and each list did for the TV; the weekly report carries both ([design decision 82](../design-decisions.md#82-each-rule-and-list-is-counted-from-the-store-an-allow-unused-for-30-days-is-named-with-the-command-that-removes-it-never-removed)). `src/tvgw/rulestats.py` reads the store's copy of AdGuard's naming: for each lookup the first rule AdGuard names (`dns.rule`) and its list's id (`dns.filter_id`). It changes nothing.

An owner's rule is matched on its exact text among the custom rules (`filter_id` 0, or NULL for a row the log file wrote before 2026-11-07): the file's line with its spaces stripped, which is what the plan writes into `user_rules` and what AdGuard names, `$important` included. A block decided a lookup it refused (`blocked = 1`); an allow decided a lookup AdGuard answered under it (`blocked = 0`, reason `NotFilteredAllowList`), whether or not a list would have refused the name. An allow is called unused when it decided nothing in the 30 days before (`STALE_DAYS`), every source that dates it (its comment line, its open row in the rule history, `rules`) puts it at least that far back, the lint takes it, and the record covers the 30 days: a first ingest run at least that old, `DB_DAYS` at least 30, and a last run within 2 hours (`FRESH`) of the window's end.

The refusals by list (`--since SINCE`, 7 days by default; `use` in the JSON) give every refusal of the window to exactly one row, so the rows add up:

| Row | The refusals it gets |
|---|---|
| A list, by the name the profile gives its URL (`namecheck.list_names()`) | `filter_id` is that list's id; every list AdGuard's settings switch on has a row, one that refused nothing included |
| A list AdGuard's settings no longer switch on | Its id, which the window still holds |
| The profile's own rules | A custom rule whose text `Profile.adguard_rules()` gives |
| Your own rules | A custom rule whose text `LOCAL_RULES` holds, or an owner's command wrote (the change ledger's `owner_rule_change` rows) |
| The gateway's own rules | A custom rule whose text `AUTO_RULES` or `auto_rules` holds |
| Rules none of tvgw's files hold now | Any other custom rule: drift, or a rule taken out of the profile since. Only when it counted something |
| AdGuard Home's own features, or no rule named | A negative `filter_id`, or no rule. Only when it counted something |

A text two sources hold goes to the first of the profile, the owner and the machine, the order `adguardcfg.rule_groups()` keeps. A row gives its five most refused names (`TOP`) with the company the snapshot names; a name that is not an internet name (`names.is_public_name()`) is counted and never printed. The lists' names and which lists are switched on come from AdGuard's settings file, which AdGuard may keep readable by root alone; read without it, the lists go by AdGuard's number, a list that refused nothing cannot be shown, and the output says so. A list that refused nothing names `sudo tvgw verify` when [a sentinel](#the-sentinels) checks that it is loaded.

## Pausing the shared lists

`sudo tvgw pause [MINUTES]` switches the profile's shared tracker lists off for at most an hour, 10 minutes by default, so the owner can see whether an app works without them, and then names what they were stopping ([design decision 79](../design-decisions.md#79-a-pause-lifts-only-the-shared-tracker-lists-for-at-most-an-hour-through-the-plan-ends-on-its-own-two-ways-and-then-names-what-the-lists-were-stopping)). It never uses AdGuard Home's own protection switch, which would also lift the URL filter's rewrites, the withheld record types and the must-allow exceptions.

| Part | How |
|---|---|
| What goes | Each `[adguard] filters` entry of `role` `tracking`, the default (`Profile.tracking_filters()`). |
| What stays | The entry of `role` `bypass`, the list of encrypted-DNS servers, which every bundled profile marks; every custom rule (the profile's, the owner's, the machine's, the generated exceptions, rewrites and record-type rule); every other key of the plan; every firewall table. |
| The state | One row of the store's `meta`, `pause`: JSON with `start`, `end` (planned), `minutes`, `lists` as (name, url) pairs, and once it is over `ended` and `how` (`timer`, `early`, `fallback`). A row that cannot be read is no pause. |
| The plan | `adguardcfg.desired()` reads the row (`listpause.paused_urls()`) and `plan()` sets `enabled: false` on the paused lists while `start <= now < end` and the row is not ended, and `enabled: true` otherwise; the bypass list is dropped from `paused` whatever the row says. Every apply renders it, so a deploy during a pause keeps it and the first apply after its end removes it. A reboot applies nothing to AdGuard Home, so after one the hourly check ends an overdue pause. |
| The start | Under the autonomy's lock, waiting up to 30 seconds: the transient timer first (`systemd-run --unit=tvgw-pause-end --on-active=<seconds> --collect`, running `tvgw --conf <conf> pause --end --timer`), then the row, then `analyst.adguardcfg_apply()` with the lists named, which lints the profile and goes through the restart guard. A timer that cannot be set, a deferred apply (exit 3) or a refused one leaves nothing paused: the row goes back and the timer is stopped. |
| The ends | The timer's `--end --timer`, the owner's `--end`, and the hourly `tvgw autoblock check`, which ends a pause past its end before it judges anything (`listpause.fallback()`). Each marks the row ended, applies with nothing paused and, if AdGuard did not take it or held the restart back, opens the row again. The timer tries every 5 minutes for 2 hours; the hourly check every hour. An end waits for the autonomy's lock (the timer 15 minutes, the owner 30 seconds, the hourly check 2 minutes) and then goes ahead without it. A held AdGuard lock (`adguardcfg.Busy`) is tried again six times, 5 seconds apart. |
| The report | `listpause.report()`: the TV's lookups in the pause's window from the query-log file and AdGuard's page, as `tvgw refused` reads them; the public names answered with no rule at all, at most `ASKED` (200), those not answered before the pause first; each asked of check_host with the lists back; the ones a paused list blocks, turned into refusals by that list's rule and ranked by `refused.judge()`, so the ranking and the fix are `tvgw refused`'s. It writes nothing. |

The time a pause takes to come in and go away is two AdGuard restarts; the namespace tier's `tests/virtual/test_virtual_pause.py` times each against the pinned binary and writes them to `pause/timings.json` in its artifacts.

## Checks on the gateway

After a deploy, on the gateway:

```sh
sudo grep -n -E 'schema_version|filters_update_interval|ignored_enabled|cache_enabled|cache_optimistic|rewrites_enabled|blocking_mode|ratelimit:|upstream_mode' /opt/AdGuardHome/AdGuardHome.yaml
sudo grep -n -A3 'edns_client_subnet:' /opt/AdGuardHome/AdGuardHome.yaml   # enabled: false, use_custom: false
systemctl show -P ExecStart AdGuardHome            # argv[] ends with --no-check-update
sudo tvgw adguard diff                              # AdGuard Home matches the profile and settings
sudo tvgw verify | grep -E 'adguard_|list_sentinels'
tvgw sql "select filter_id, count(*) from dns where blocked=1 group by 1"
sudo tvgw refused --json --since 1h | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["read_log"], d["asked_adguard"], d["complete"])'   # True True True
```
