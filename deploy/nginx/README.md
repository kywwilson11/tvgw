# The URL filter and TLS passthrough

This folder holds the two nginx files that filter LG's plain-HTTP file service (GFTS) by URL and hand its HTTPS through by server name, undecrypted. `install.sh` writes both into place on every run when nginx is installed. Why the file service gets a URL filter instead of a DNS block is in [design decision 8](../../docs/design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block).

## Files

| File | What it is | Installed as |
|---|---|---|
| `tvgw-gfts.conf` | Port 80 on `10.10.10.1`: the URL filter and its log format. | `/etc/nginx/conf.d/tvgw-gfts.conf` |
| `stream.conf` | Port 443 on `10.10.10.1`: TLS passthrough by server name. Needs `libnginx-mod-stream`. | `/etc/nginx/tvgw/stream.conf`, included at the top level of `/etc/nginx/nginx.conf` |

`install.sh` replaces `__RESOLVER__` in both with `URL_FILTER_RESOLVER` ([the settings file](../README.md#the-settings-file)), adds the stream include once, and removes nginx's default site ([what install.sh does](../README.md#what-installsh-does)).

## How a request reaches nginx

The GFTS hosts carry both what the TV needs, app packages and icons, and what it does not: the ACR configuration file, the telemetry schedule, LG Shopping data, home-screen promo thumbnails and the LG Channels guide. DNS cannot split one host. So `tvgw adguard apply` generates one `||host^$dnsrewrite=<GW_IP>` rule for each host in the profile's `[url_filter] hosts` ([the profile format](../../docs/adding-a-profile.md#the-profile-format)), AdGuard answers those names with the gateway's address, and the TV connects to nginx on the Pi.

## The URL filter, line by line

`tvgw-gfts.conf`, in order:

| Line | Why |
|---|---|
| `log_format tvgw_gfts '$time_iso8601 $remote_addr $status $body_bytes_sent $request_time "$host" "$request_uri" "$http_user_agent" $request_method $request_length "$upstream_status"';` | The format `tvgw.gfts.parse_line` reads. New fields go at the end, so older lines still parse. |
| `listen 10.10.10.1:80 default_server;` | The TV-facing address only. |
| `server_name ngfts.lge.com aic-ngfts.lge.com aic-img-ngfts.lge.com gfts.lge.com;` | The profile's URL-filter hosts. |
| `access_log /var/log/tvgw/gfts.log tvgw_gfts;` | Every request is logged; the hourly ingest loads the TV's lines. |
| `resolver __RESOLVER__ valid=300s ipv6=off;` | The real names are resolved with `URL_FILTER_RESOLVER`, never with AdGuard, which would answer with this address again. |
| `if ($request_uri ~* "biz_code=(PREMIUM\|CDP\|LGSHOPPING\|MAS\|IBS)([&_]\|$)") { return 403; }` | Refuses the side channels, matched case-insensitively. |
| `if ($host !~* "^(aic-\|aic-img-)?n?gfts\.lge\.com$") { return 444; }` | Only the rewritten names belong here; 444 closes a misrouted request without a response. |
| `location /` with `proxy_pass http://$host$request_uri;` | Everything else goes to the real host. |
| `proxy_set_header Host $host;`, `proxy_http_version 1.1;`, `proxy_set_header Connection "";` | The upstream request carries the TV's host name over HTTP/1.1. |
| `proxy_buffering off;` | Responses pass to the TV as they arrive, unbuffered. |
| `proxy_connect_timeout 10s;`, `proxy_read_timeout 300s;` | 10 seconds to connect, 300 seconds (5 minutes) between reads. |
| `client_max_body_size 64m;` | Request bodies up to 64 MB. |

The `biz_code` values the regex refuses, as the file's header describes them:

| Code | What it carries |
|---|---|
| `CDP` | The telemetry schedule. |
| `IBS` | The LG Channels guide and channel art. |
| `LGSHOPPING` | LG Shopping data and images. |
| `MAS` | Home-screen promo thumbnails. |
| `PREMIUM` | The ACR configuration file. |

App Store packages and icons (`APP_STORE`, `SVCSH`, `META_IMG`) and every other code pass. The filter is a deny list.

The log's last three fields arrived on 2026-10-27; a line without them still parses, with those fields empty. `$upstream_status` is `-` when nginx answered by itself, which is how the filter's own 403 is told from one LG's host sent back (`GftsRequest.blocked` in src/tvgw/gfts.py). nginx joins several upstream attempts with `, `, hence the quotes. The hourly ingest stores the TV's requests in the `http` table with `src='gfts'` ([tables](../../docs/data-model.md#tables)). The rule-history ingest reads the regex from the installed file, from the exact `$request_uri ~* "..."` shape.

## The TLS passthrough, line by line

`stream.conf`, inside one `stream { }` block:

| Line | Why |
|---|---|
| `log_format tvgw_tls '$time_iso8601 $remote_addr $status $bytes_sent $bytes_received $session_time "$ssl_preread_server_name"';` | One line per TLS session. |
| `resolver __RESOLVER__ valid=300s ipv6=off;` | As in the URL filter. |
| `map $ssl_preread_server_name $tvgw_upstream { ~^(aic-\|aic-img-)?n?gfts\.lge\.com$ $ssl_preread_server_name; default ""; }` | Only the URL-filter names get an upstream. Any other name gets none, and its connection fails. |
| `listen 10.10.10.1:443;` | The TV-facing address only. |
| `ssl_preread on;` | nginx reads the server name from the ClientHello without decrypting anything. |
| `access_log /var/log/tvgw/gfts-tls.log tvgw_tls;` | Rotated with the other logs and never ingested. |
| `proxy_pass $tvgw_upstream:443;` | The TLS session goes to the real host. |
| `proxy_connect_timeout 10s;`, `proxy_timeout 300s;` | 10 seconds to connect, 300 seconds (5 minutes) idle. |

The Content Store also reaches the GFTS names over HTTPS, which is why the names AdGuard rewrites need a listener on 443 too.

## Checking it

nginx listens only on `10.10.10.1`, so these run on the Pi; the first three are what the hardware suite runs.

On the Pi:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: ngfts.lge.com' 'http://10.10.10.1/fts/gftsDownload.lge?biz_code=PREMIUM&func_code=ACR&file_path=/x'      # 403
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: ngfts.lge.com' 'http://10.10.10.1/fts/gftsDownload.lge?biz_code=APP_STORE&func_code=APP_ICON&file_path=/appstore/app/icon/20250220/38386090.png'   # 200
curl -s -o /dev/null -w '%{http_code} %{ssl_verify_result}\n' --resolve gfts.lge.com:443:10.10.10.1 https://gfts.lge.com/      # a status other than 000, verify result 0
sudo nginx -t                                  # the installed config parses
ss -ltn '( sport = :80 or sport = :443 )'      # listeners on 10.10.10.1 only
tvgw gfts 1d                                   # the TV's requests by status and biz_code
```

`sudo tvgw verify` checks that each URL-filter host resolves to the gateway and that nginx is running ([what tvgw verify checks](../../docs/troubleshooting.md#what-tvgw-verify-checks)).

## Changing it

The regex and the host list live in the profile and in these files, and nothing generates one from the other.

1. Edit `block_regex` or `hosts` under `[url_filter]` in `src/tvgw/profiles/lg-webos.toml`.
2. Make the same change here: the `$request_uri ~* "..."` line, the `server_name` list and the `$host` check in `tvgw-gfts.conf`, and the `map` pattern in `stream.conf`. Keep the `~* "..."` shape, which the rule-history ingest reads.
3. Run `make gate`. `test_nginx_conf_matches_the_profile` in tests/unit/test_profile.py fails until the regex, the `server_name` list, the host check and the passthrough map agree with the profile. `test_the_parser_reads_exactly_the_deployed_log_format` in tests/unit/test_gfts.py fails when the `log_format` line and the parser disagree.
4. Deploy. The hardware suite checks that the installed files equal these templates with the resolver filled in, that the installed regex is the profile's, and that the filter blocks and passes the URLs above.

A hand edit of the installed file takes effect with `sudo systemctl reload nginx`, lasts until the next install overwrites it, and fails the hardware suite meanwhile.

## Gotchas

- The 403 check comes before the host check, so a refused `biz_code` gets 403 on any host.
- A new `biz_code` passes until it is added to the regex.
- If nginx is down, app installs and updates fail. `tvgw verify`'s `services` check reports it.
- The generated `$dnsrewrite` rules follow `GW_IP`; these files hardcode `10.10.10.1`, so changing `GW_IP` alone moves the rewrites and not the listener.
- `install.sh` installs these files whenever nginx is present, whatever the profile.
