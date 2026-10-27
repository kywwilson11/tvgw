# nginx: the URL filter and the TLS passthrough

LG's GFTS file service mixes what the TV needs (app packages and icons) with what it does not (the ACR configuration file, the telemetry schedule, LG Shopping data, home-screen promo thumbnails, the LG Channels guide), all over plain HTTP and on the same host names. DNS cannot split one host, so AdGuard Home answers those names with the gateway's address and nginx on the Pi filters by URL. Why this and not a block: [../../docs/design-decisions.md](../../docs/design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block).

## Files

| File | Installed as | What it does |
|---|---|---|
| `tvgw-gfts.conf` | `/etc/nginx/conf.d/tvgw-gfts.conf` | Port 80 on `10.10.10.1`: the URL filter. |
| `stream.conf` | `/etc/nginx/tvgw/stream.conf`, included at the top level of `/etc/nginx/nginx.conf` | Port 443 on `10.10.10.1`: TLS passthrough by server name. Needs `libnginx-mod-stream`. |

`install.sh` replaces `__RESOLVER__` in both with `URL_FILTER_RESOLVER` (default `1.1.1.1`) and removes nginx's default site.

## How a request is handled

The TV asks AdGuard for `ngfts.lge.com`, `aic-ngfts.lge.com`, `aic-img-ngfts.lge.com` or `gfts.lge.com`. The `$dnsrewrite` rules in `lg-webos.rules` answer `10.10.10.1`. The TV then connects to nginx.

**Port 80** (`tvgw-gfts.conf`), in order:

1. If the request URI matches `biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)`, case-insensitively, return 403.
2. If the `Host` is not one of the GFTS names, return 444 (close without a response): nothing else belongs here.
3. Otherwise proxy to the real host, resolved with `URL_FILTER_RESOLVER`, without buffering, with up to 64 MB request bodies and a 300 s read timeout.

Every request is logged to `/var/log/tvgw/gfts.log` as `time client status bytes request_time "host" "uri" "user_agent"`. `tvgw ingest` loads the TV's lines into the `http` table with `src='gfts'`, and `tvgw gfts` and the brief tally them by status and `biz_code`.

**Port 443** (`stream.conf`). The Content Store also reaches the GFTS names over HTTPS. nginx reads the server name from the ClientHello (`ssl_preread`) and, for names matching `^(aic-|aic-img-)?n?gfts\.lge\.com$`, passes the TLS session to the real host without decrypting it. Any other name gets no upstream and the connection fails. Sessions are logged to `/var/log/tvgw/gfts-tls.log`; that log is rotated but not ingested.

## The resolver setting

nginx must not ask AdGuard for the real addresses, because AdGuard rewrites those names to the gateway. `URL_FILTER_RESOLVER` sets which resolver it uses instead. nginx's own lookups and its upstream connections are the Pi's own traffic, so with a VPN client on the Pi they follow the VPN's routes. If the VPN client blocks DNS to anything but its own resolver, set `URL_FILTER_RESOLVER` to that resolver and re-run `install.sh`.

## Testing with curl

Run these on the Pi; nginx listens only on `10.10.10.1`. They are what the hardware suite runs.

```sh
# a blocked side channel: expect 403
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: ngfts.lge.com' \
  'http://10.10.10.1/fts/gftsDownload.lge?biz_code=PREMIUM&func_code=ACR&file_path=/x'

# an app icon: expect 200
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: ngfts.lge.com' \
  'http://10.10.10.1/fts/gftsDownload.lge?biz_code=APP_STORE&func_code=APP_ICON&file_path=/appstore/app/icon/20250220/38386090.png'

# TLS passthrough: expect a status other than 000 and verify result 0
curl -s -o /dev/null -w '%{http_code} %{ssl_verify_result}\n' \
  --resolve gfts.lge.com:443:10.10.10.1 https://gfts.lge.com/
```

`sudo tvgw verify` also checks that each URL-filter host resolves to the gateway (`resolver_rewrite`) and that nginx is running.

## Changing the filter

The regex lives in two places: `block_regex` in `src/tvgw/profiles/lg-webos.toml` and the `if ($request_uri ~* "...")` line in `tvgw-gfts.conf`. Change both. The hardware suite checks that the installed nginx file contains the profile's regex, and the rule-history ingest reads the regex from that exact `~* "..."` shape, so keep it. Deploy, or on the Pi `sudo systemctl reload nginx` after editing the installed file (the next install overwrites it).

## Gotchas

- The filter is a deny list. A new `biz_code` passes until you add it.
- The 403 check comes before the host check, so a blocked `biz_code` gets 403 on any host.
- The header comment in `tvgw-gfts.conf` says the upstream is resolved "through PIA's resolver"; it is whatever `URL_FILTER_RESOLVER` says.
- If nginx is down, app installs and updates fail. `tvgw verify`'s `services` check reports it.
