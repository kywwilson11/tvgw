# The URL filter and TLS passthrough

This folder holds the two nginx files that filter LG's plain-HTTP file service (GFTS) by URL and hand its HTTPS through by server name, undecrypted. `install.sh` writes both into place on every run when nginx is installed. Why the file service gets a URL filter instead of a DNS block is in [design decision 8](../../docs/design-decisions.md#8-a-url-filter-for-lgs-file-service-instead-of-a-dns-block).

## Files

| File | What it is | Installed as |
|---|---|---|
| `tvgw-gfts.conf` | Port 80 on `GW_IP` (`10.10.10.1` by default): the URL filter and its log format. | `/etc/nginx/conf.d/tvgw-gfts.conf` |
| `stream.conf` | Port 443 on `GW_IP`: TLS passthrough by server name. Needs `libnginx-mod-stream`. | `/etc/nginx/tvgw/stream.conf`, included at the top level of `/etc/nginx/nginx.conf` |
| `tvgw-hardening.conf` | The sandbox lines for `nginx.service` ([the sandbox](#the-sandbox)). | Appended to `/etc/systemd/system/nginx.service.d/tvgw.conf` by `install.sh` |

`install.sh` replaces `__RESOLVER__` in both with `URL_FILTER_RESOLVER` and `__GW_IP__` with `GW_IP` ([the settings file](../../docs/reference/settings.md)), adds the stream include once, and removes nginx's default site ([what install.sh does](../README.md#what-installsh-does)).

## The sandbox

nginx's workers parse the TV's HTTP requests and TLS hellos, and Debian's `nginx.service` has no sandbox. `install.sh` writes the drop-in `nginx.service.d/tvgw.conf` with the start order and `Restart=on-failure`, then the lines of `tvgw-hardening.conf` ([design decision 42](../../docs/design-decisions.md#42-the-pi-is-closed-to-the-tv-whatever-nftables-holds)):

- `CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_KILL`. `CAP_KILL` lets the root master signal workers that run as `www-data` when the channel to them fails (`ngx_signal_worker_processes`).
- `NoNewPrivileges`, `ProtectSystem=strict` with `/var/log/nginx`, `/var/log/tvgw`, `/var/lib/nginx` and `/run` writable, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, the kernel protections, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `SystemCallArchitectures=native` and `SystemCallFilter=@system-service`.
- `RestrictAddressFamilies=AF_INET AF_NETLINK AF_UNIX`, with `AF_INET6` added when `nginx -T` shows a `listen [` address. `AF_NETLINK` is for glibc's `getaddrinfo`, which a config naming an upstream by host name needs.
- `MemoryDenyWriteExecute=yes`, only when `nginx -T` shows no `pcre_jit on`: PCRE2's JIT needs writable executable memory.

A sandbox applies only when nginx starts, so when the drop-in changed `install.sh` restarts nginx once (otherwise it reloads it, which keeps the passthrough and downloads in progress) and checks that nginx is active and listening on `GW_IP:80` and `GW_IP:443`. If not, the drop-in goes back to the start order and restarts alone, nginx restarts, the install prints a `WARNING`, and, once nginx serves without the sandbox, `/var/lib/tvgw/.unit-stamps/nginx-refused` keeps the next deploy from trying the same sandbox again. An nginx that does not serve either way stops the install and leaves no stamp.

## How a request reaches nginx

The GFTS hosts carry both what the TV needs, app packages and icons, and what it does not: the ACR configuration file, the telemetry schedule, LG Shopping data, home-screen promo thumbnails and the LG Channels guide. DNS cannot split one host. So `tvgw adguard apply` generates one `||host^$dnsrewrite=<GW_IP>` rule for each host in the profile's `[url_filter] hosts` ([the profile format](../../docs/reference/profile-format.md)), AdGuard answers those names with the gateway's address, and the TV connects to nginx on the gateway.

## The URL filter, line by line

`tvgw-gfts.conf`, in order:

| Line | Why |
|---|---|
| `log_format tvgw_gfts '$time_iso8601 $remote_addr $status $body_bytes_sent $request_time "$host" "$request_uri" "$http_user_agent" $request_method $request_length "$upstream_status"';` | The format `tvgw.gfts.parse_line` reads. New fields go at the end, so older lines still parse. |
| `listen __GW_IP__:80 default_server;` | The TV-facing address only: `GW_IP`, filled in by `install.sh`. |
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

The log's last three fields arrived on 2026-10-27; a line without them still parses, with those fields empty. `$upstream_status` is `-` when nginx answered by itself, which is how the filter's own 403 is told from one LG's host sent back (`GftsRequest.blocked` in src/tvgw/gfts.py). nginx joins several upstream attempts with `, `, hence the quotes. The hourly ingest stores the TV's requests in the `http` table with `src='gfts'` ([tables](../../docs/reference/data-model.md#tables)). The rule-history ingest reads the regex from the installed file, from the exact `$request_uri ~* "..."` shape.

## The TLS passthrough, line by line

`stream.conf`, inside one `stream { }` block:

| Line | Why |
|---|---|
| `log_format tvgw_tls '$time_iso8601 $remote_addr $status $bytes_sent $bytes_received $session_time "$ssl_preread_server_name"';` | One line per TLS session. |
| `resolver __RESOLVER__ valid=300s ipv6=off;` | As in the URL filter. |
| `map $ssl_preread_server_name $tvgw_upstream { ~^(aic-\|aic-img-)?n?gfts\.lge\.com$ $ssl_preread_server_name; default ""; }` | Only the URL-filter names get an upstream. Any other name gets none, and its connection fails. |
| `listen __GW_IP__:443;` | The TV-facing address only: `GW_IP`, filled in by `install.sh`. |
| `ssl_preread on;` | nginx reads the server name from the ClientHello without decrypting anything. |
| `access_log /var/log/tvgw/gfts-tls.log tvgw_tls;` | Rotated with the other logs and never ingested. |
| `proxy_pass $tvgw_upstream:443;` | The TLS session goes to the real host. |
| `proxy_connect_timeout 10s;`, `proxy_timeout 300s;` | 10 seconds to connect, 300 seconds (5 minutes) idle. |

The Content Store also reaches the GFTS names over HTTPS, which is why the names AdGuard rewrites need a listener on 443 too.

## Checking it

nginx listens only on `GW_IP`, so these run on the gateway (shown with the default `10.10.10.1`); the first three are what the hardware suite runs.

On the gateway:

```sh
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: ngfts.lge.com' 'http://10.10.10.1/fts/gftsDownload.lge?biz_code=PREMIUM&func_code=ACR&file_path=/x'      # 403
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: ngfts.lge.com' 'http://10.10.10.1/fts/gftsDownload.lge?biz_code=APP_STORE&func_code=APP_ICON&file_path=/appstore/app/icon/20250220/38386090.png'   # 200
curl -s -o /dev/null -w '%{http_code} %{ssl_verify_result}\n' --resolve gfts.lge.com:443:10.10.10.1 https://gfts.lge.com/      # a status other than 000, verify result 0
sudo nginx -t                                  # the installed config parses
ss -ltn '( sport = :80 or sport = :443 )'      # listeners on 10.10.10.1 only
tvgw gfts 1d                                   # the TV's requests by status and biz_code
```

`sudo tvgw verify` checks that each URL-filter host resolves to the gateway and that nginx is running ([what tvgw verify checks](../../docs/reference/verify-checks.md)).

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
- The generated `$dnsrewrite` rules and both `listen` lines follow `GW_IP` (`install.sh` fills in `__GW_IP__`), so a changed `GW_IP` needs `install.sh` and then `tvgw adguard apply`, which the installer runs.
- `install.sh` installs these files whenever nginx is present, whatever the profile.
