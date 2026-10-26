# tvgw — a Raspberry Pi gateway that watches the TV that watches you

A smart TV plugs into the Pi's Ethernet port and the Pi becomes its only way out. From there:

- **Isolation** — nftables keeps the TV off your LAN (no device scanning, no mDNS/SSDP inventory),
  forces every DNS lookup through a local AdGuard Home, and rejects DNS-over-HTTPS/TLS/QUIC so
  the TV can't route around the filter. Everything it asks for is answered by you.
- **Observation** — tcpdump keeps handshakes and plain HTTP, conntrack keeps byte counts per
  connection, AdGuard keeps every query with the rule that matched, nginx logs the vendor's
  plain-HTTP file service, and the TV's own LAN API reports its settings hourly. All of it lands
  in one SQLite database (`tvgw.db`, about 1 MB per day) that the `tvgw` CLI queries.
- **Filtering** — DNS blocklists plus a per-TV profile of what to block and what must stay
  allowed, and a URL filter for the things DNS can't separate (the LG file service carries both
  app installs and the ACR configuration file).

Vendor knowledge lives in **profiles** (`src/tvgw/profiles/`), so a different TV is a new profile,
not a new program. The bundled `lg-webos` profile was built from an LG CX (webOS 5) observed for
several days; see `docs/lg-cx-deployment.md` for that deployment and its findings.

## What it found on an LG CX (October 2026)

- ACR (screen fingerprinting via Alphonso) phones its provisioning host even with *Live Plus* off;
  the ACR client re-fetches its config over plain HTTP from `ngfts.lge.com` on every boot.
- Universal Electronics device fingerprinting (`ueiwsp.com`) is tried about once a minute.
- The TV scans the LAN (SSDP, mDNS, LIFX, CoAP, TP-Link) constantly and probes networks it
  remembers from elsewhere. There is no menu setting for this. Isolation handles it.
- The Content Store depends on `us.lgrecommends.lgappstv.com` and app installs on the GFTS hosts;
  blocking either breaks installs. The URL filter exists because of this.
- Prime Video's ads are stitched into the stream from the same CDN as the show; DNS cannot remove
  them. Peacock's, Disney+'s, Netflix's and Prime's telemetry endpoints can all be blocked without
  breaking playback (each verified).
- The CX has no built-in microphone; with the *Voice Information* agreement declined a press on the
  remote's mic button produces a consent prompt and zero network activity. Speech back-ends are
  blocked anyway.

## Layout

```
src/tvgw/            the package: parsers (conntrack, dnsmsg, adguard, gfts, tshark, logtail),
                     config, profile, db/ingest/queries, cli, report, lgwebos
src/tvgw/profiles/   lg-webos.toml (categories, must-allow, URL filter) + lg-webos.rules (AdGuard rules)
deploy/              what runs on the Pi: install.sh, nftables/tvgw-apply, systemd units, nginx,
                     dnsmasq template, NetworkManager, logrotate, shell glue (bin/)
tests/unit/          pytest, fixtures are verbatim captured lines; mutation-tested with mutmut
tests/hardware/      pytest -m hardware, run on the Pi against the live gateway
docs/                deployment notes and research
```

## Install on the Pi

```sh
sudo apt install tcpdump conntrack dnsmasq tshark nginx libnginx-mod-stream python3-venv
# AdGuard Home: native install, DNS on :53, UI bound to 127.0.0.1:3000 (docs/lg-cx-deployment.md)
git clone <this repo> /opt/tvgw/src && cd /opt/tvgw/src/deploy
sudo cp tvgw.conf.example /etc/tvgw/tvgw.conf && sudo nano /etc/tvgw/tvgw.conf   # TV_MAC, TV_IP, WAN_*
sudo ./install.sh
```

Paste `src/tvgw/profiles/lg-webos.rules` into AdGuard's custom filtering rules (it includes the
`$dnsrewrite` rules that point the GFTS hosts at the gateway), enable the HaGeZi LG webOS, DoH
bypass and Pro lists, set upstreams to DoH-by-IP. Then watch:

```sh
tvgw brief                 # yesterday: lookups, new hosts, blocked retries, uploads, URL filter, TV state
tvgw new-hosts 3d          # names first seen in the last three days, with their blocked state
tvgw retries 1d            # blocked names the TV keeps asking for
tvgw allowed 1d            # allowed non-streaming names: the candidates for new rules
tvgw host alphonso.tv      # everything about one name
tvgw sql "select ..."      # anything else, read-only
sudo tvgw ingest           # runs hourly from tvgw-analyze.timer; safe to run by hand
```

Daily reports (`/var/lib/tvgw/reports/daily/`) are written at 00:20 and end with the
unexpected-port log, the TV's hourly power state and the URL-filter tallies.

## Development

```sh
make dev        # pip install -e ".[dev]"
make lint       # ruff check + format
make test       # unit tests
make mutmut     # mutation testing (slow)
make hardware   # hardware suite on the Pi (PI=host)
make deploy     # rsync + install.sh on the Pi
```

Rules of the repo: parsers are pure functions with real captured lines as fixtures; anything that
touches the Pi (files, tshark, journalctl) is injected so ingest is testable; site identifiers
(MACs, LAN addresses, ZIP codes) never go in — they live in `/etc/tvgw/tvgw.conf`.

## Adding a TV

1. Deploy the gateway with `PROFILE=lg-webos` anyway — isolation, capture and the store are
   vendor-neutral, and the report's "Other" category will show you what the new TV talks to.
2. After a few days, `tvgw allowed 7d` and `tvgw top-upload 7d` are the raw material: name the
   vendor's telemetry/ads/fingerprinting hosts, find what breaks when blocked (the store, clock,
   firmware), and write `src/tvgw/profiles/<vendor>.toml` + `.rules`. Community lists (HaGeZi,
   Perflyst) are a starting point, not an answer; the capture is.
3. Set `PROFILE=<vendor>` and reinstall.

## Status

Working and deployed on one gateway; unit suite green; hardware suite exists; the legacy
`tvgw report` still reads the hourly text files rather than the database (next up), and the
Luna-side writes to LG TVs are read-only on current firmware (needs root for more). See
`CHANGELOG.md`.

## License

MIT.
