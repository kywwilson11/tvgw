"""nginx URL-filter log lines (verbatim from /var/log/tvgw/gfts.log) and biz_code handling."""

from tvgw.gfts import biz_code, parse_line

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


def test_garbage_lines():
    assert parse_line("") is None
    assert parse_line("==> /var/log/tvgw/gfts.log <==") is None
    assert parse_line('nope 10.10.10.17 403 153 0.000 "h" "/" "ua"') is None  # bad time


def test_biz_code_extraction():
    assert biz_code("/x?biz_code=LGSHOPPING&func_code=DATA") == "LGSHOPPING"
    assert biz_code("/x?func_code=DATA&biz_code=APP_STORE") == "APP_STORE"
    assert biz_code("/x?biz_code=") is None
    assert biz_code("/plain/path") is None
