"""AdGuard Home query-log records and user-rules YAML handling."""

from tvgw.adguard import parse_querylog_line, parse_time, replace_user_rules, user_rules_from_yaml

BLOCKED = (
    '{"T":"2026-10-26T09:14:37.101138599-05:00","QH":"aic.recommend.lgtvcommon.com","QT":"AAAA","QC":"IN","CP":"",'
    '"Answer":"80CBgAABAAEAAAAAA0FJQwlyZWNvbW1lbmQKbGd0dmNvbW1vbgNjb20AABwAAcAMABwAAQAAADwAEAAAAAAAAAAAAAAAAAAAAAA=",'
    '"IP":"10.10.10.17","Result":{"Rules":[{"Text":"||recommend.lgtvcommon.com^"}],"Reason":3,"IsFiltered":true},'
    '"Elapsed":264779}'
)
ALLOWED = (
    '{"T":"2026-10-26T09:14:37.101045506-05:00","QH":"us.lgtvsdp.com","QT":"A","QC":"IN","CP":"",'
    '"Upstream":"https://1.0.0.1:443/dns-query",'
    '"Answer":"FhyBgAABAAIAAAAAAlVTB2xndHZzZHADY29tAAABAAHADAAFAAEAAAAMABwOdXMtbGd0dnNkcC1jb20HYXdzLXByZANuZXQAwCwAAQABAAAADAAEI6a9RA==",'
    '"IP":"10.10.10.17","Result":{"Rules":[{"Text":"@@||us.lgtvsdp.com^","FilterListID":0}],"Reason":1},'
    '"Elapsed":34704,"Cached":true}'
)
YAML = """http:
  address: 127.0.0.1:3000
user_rules:
  - '@@||us.lgtvsdp.com^'
  - '||alphonso.tv^'
  - '||ngfts.lge.com^$dnsrewrite=10.10.10.1'
dhcp:
  enabled: false
"""


def test_blocked_record():
    r = parse_querylog_line(BLOCKED)
    assert r is not None
    assert (r.qname, r.qtype, r.client) == ("aic.recommend.lgtvcommon.com", "AAAA", "10.10.10.17")
    assert r.blocked and r.reason == "FilteredBlockList"
    assert r.rule == "||recommend.lgtvcommon.com^" and r.filter_id is None
    assert r.answers == "AAAA:0:0:0:0:0:0:0:0"
    assert r.upstream is None and not r.cached
    assert abs(r.elapsed_ms - 0.264779) < 1e-9


def test_allowed_record_keeps_rule_upstream_and_cache_flag():
    r = parse_querylog_line(ALLOWED)
    assert r is not None
    assert not r.blocked and r.reason == "NotFilteredAllowList"
    assert r.rule == "@@||us.lgtvsdp.com^" and r.filter_id == 0
    assert r.upstream == "https://1.0.0.1:443/dns-query" and r.cached
    assert r.answers == "CNAME:us-lgtvsdp-com.aws-prd.net,A:35.166.189.68"


def test_client_filter_and_malformed_lines():
    assert parse_querylog_line(BLOCKED, client="10.10.10.17") is not None
    assert parse_querylog_line(BLOCKED, client="192.168.4.33") is None
    assert parse_querylog_line("{not json") is None
    assert parse_querylog_line("[1,2,3]") is None
    assert parse_querylog_line('{"T":"garbage","QH":"x"}') is None


def test_unknown_reason_code_is_kept_as_text():
    r = parse_querylog_line(BLOCKED.replace('"Reason":3', '"Reason":99'))
    assert r is not None and r.reason == "99"


def test_record_without_answer_or_rules():
    r = parse_querylog_line(
        '{"T":"2026-10-26T09:14:37Z","QH":"Example.COM.","QT":"A","IP":"1.2.3.4","Result":{}}'
    )
    assert r is not None
    assert r.qname == "example.com" and r.answers is None and r.rule is None
    assert r.reason == "NotFilteredNotFound" and not r.blocked


def test_parse_time_variants():
    assert parse_time("2026-10-26T09:14:37.101138599-05:00") == parse_time("2026-10-26T09:14:37.101138-05:00")
    assert parse_time("2026-10-26T14:14:37Z") == parse_time("2026-10-26T09:14:37-05:00")
    assert parse_time("2026-10-26 09:14:37") is not None  # naive = local time
    assert parse_time("yesterday") is None
    assert parse_time("2026-13-45T00:00:00Z") is None


def test_user_rules_round_trip():
    rules = user_rules_from_yaml(YAML)
    assert rules == ["@@||us.lgtvsdp.com^", "||alphonso.tv^", "||ngfts.lge.com^$dnsrewrite=10.10.10.1"]
    new = replace_user_rules(YAML, [*rules, "||example.com^"])
    assert user_rules_from_yaml(new) == [*rules, "||example.com^"]
    assert new.startswith("http:\n") and new.endswith("dhcp:\n  enabled: false\n")
    emptied = replace_user_rules(YAML, [])
    assert user_rules_from_yaml(emptied) == []
    assert "dhcp:" in emptied
