"""nginx URL-filter log lines (verbatim from /var/log/tvgw/gfts.log) and biz_code handling."""

import re
from pathlib import Path

from tvgw.gfts import biz_code, parse_line

CONF = Path(__file__).resolve().parents[2] / "deploy" / "nginx" / "tvgw-gfts.conf"

BLOCKED = (
    '2026-10-26T09:11:13-05:00 10.10.10.17 403 153 0.000 "ngfts.lge.com" '
    '"/fts/gftsDownload.lge?biz_code=PREMIUM&func_code=ACR&file_path=/premium/acr/acr0144234_[20221221085916]w20o_us_540.xml" '
    '"Mozila/4.0"'
)
ALLOWED = (
    '2026-10-26T09:06:31-05:00 10.10.10.1 200 6488 0.543 "ngfts.lge.com" '
    '"/fts/gftsDownload.lge?biz_code=APP_STORE&func_code=APP_ICON&file_path=/appstore/app/icon/20250220/38386090.png" '
    '"curl/7.88.1"'
)
MISROUTED = '2026-10-26T09:06:37-05:00 10.10.10.1 444 0 0.000 "example.com" "/" "curl/7.88.1"'
# the format since 2026-10-27: method, request length and who answered
POSTED_BLOCKED = (
    '2026-10-27T10:11:13-05:00 10.10.10.17 403 153 0.000 "ngfts.lge.com" '
    '"/fts/gftsDownload.lge?biz_code=CDP&func_code=SCHEDULE_FILE" "Mozila/4.0" POST 412 "-"'
)
PROXIED_403 = (
    '2026-10-27T10:12:02-05:00 10.10.10.17 403 27 0.188 "ngfts.lge.com" '
    '"/fts/gftsDownload.lge?biz_code=APP_STORE&func_code=APP_ICON&file_path=/gone.png" "Mozila/4.0" GET 388 "403"'
)


def test_blocked_acr_config_request():
    r = parse_line(BLOCKED)
    assert r is not None
    assert (r.client, r.status, r.bytes, r.host) == ("10.10.10.17", 403, 153, "ngfts.lge.com")
    assert r.biz_code == "PREMIUM" and r.blocked
    assert r.user_agent == "Mozila/4.0"


def test_allowed_app_icon_request():
    r = parse_line(ALLOWED)
    assert r is not None
    assert r.status == 200 and not r.blocked and r.biz_code == "APP_STORE"
    assert r.bytes == 6488


def test_request_without_biz_code():
    r = parse_line(MISROUTED)
    assert r is not None and r.biz_code is None and r.status == 444
    assert (r.method, r.request_length, r.upstream_status) == (None, None, None)  # the older format


def test_new_format_lines_carry_method_length_and_who_answered():
    r = parse_line(POSTED_BLOCKED)
    assert (r.method, r.request_length, r.upstream_status) == ("POST", 412, None)
    assert r.blocked and r.biz_code == "CDP"
    proxied = parse_line(PROXIED_403)
    assert (proxied.status, proxied.upstream_status, proxied.method) == (403, "403", "GET")
    assert not proxied.blocked  # LG's own 403, passed through: not the filter's doing


def test_the_parser_reads_exactly_the_deployed_log_format():
    """Ties the regex to the `log_format` line in deploy/nginx/tvgw-gfts.conf: every $variable there
    is substituted with a sample value and must come back from the field it belongs to."""
    (fmt,) = re.findall(r"^log_format tvgw_gfts '(.*)';$", CONF.read_text(), re.MULTILINE)
    sample = {
        "time_iso8601": "2026-10-27T10:11:13-05:00",
        "remote_addr": "10.10.10.17",
        "status": "403",
        "body_bytes_sent": "153",
        "request_time": "0.250",
        "host": "NGFTS.lge.com",
        "request_uri": "/fts/gftsDownload.lge?biz_code=MAS&func_code=META_THUMBNAIL",
        "http_user_agent": "Mozila/4.0 (Web0S)",
        "request_method": "GET",
        "request_length": "512",
        "upstream_status": "502, 200",  # nginx's spelling for two upstream attempts
    }
    variables = re.findall(r"\$(\w+)", fmt)
    assert sorted(variables) == sorted(sample)  # a variable added or dropped on either side fails here
    r = parse_line(re.sub(r"\$(\w+)", lambda m: sample[m.group(1)], fmt))
    assert (r.client, r.status, r.bytes, r.host, r.uri) == (
        "10.10.10.17",
        403,
        153,
        "ngfts.lge.com",
        sample["request_uri"],
    )
    assert (r.user_agent, r.method, r.request_length, r.upstream_status) == (
        sample["http_user_agent"],
        "GET",
        512,
        "502, 200",
    )
    assert not r.blocked  # answered upstream


def test_garbage_lines():
    assert parse_line("") is None
    assert parse_line("==> /var/log/tvgw/gfts.log <==") is None
    assert parse_line('nope 10.10.10.17 403 153 0.000 "h" "/" "ua"') is None  # bad time


def test_biz_code_extraction():
    assert biz_code("/x?biz_code=LGSHOPPING&func_code=DATA") == "LGSHOPPING"
    assert biz_code("/x?func_code=DATA&biz_code=APP_STORE") == "APP_STORE"
    assert biz_code("/x?biz_code=") is None
    assert biz_code("/plain/path") is None
