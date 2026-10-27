"""AdGuard Home query-log records and user-rules YAML handling."""

import pytest

from tvgw.adguard import parse_querylog_line, parse_time, user_rules_from_yaml

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


def test_client_filter():
    assert parse_querylog_line(BLOCKED, client="10.10.10.17") is not None
    assert parse_querylog_line(BLOCKED, client="192.0.2.33") is None


@pytest.mark.parametrize("line", ["{not json", "[1,2,3]", '{"T":"garbage","QH":"x"}', "\x00" * 16, ""])
def test_a_line_that_is_not_a_record_raises(line):
    """Not JSON, not an object, no readable time: the caller counts these; they are never silently None."""
    with pytest.raises(ValueError, match="not a query-log record"):
        parse_querylog_line(line)


def test_oddly_typed_fields_are_coerced_so_the_row_always_binds():
    """One record the database cannot bind would roll back the whole batch and the cursor with it, so
    every stored field has exactly its column's type whatever AdGuard wrote."""
    odd = (
        '{"T":"2026-10-26T09:14:37Z","QH":"x.example","IP":"1.2.3.4","Upstream":5,"Answer":123,'
        '"Result":{"Rules":[{"Text":{"a":1},"FilterListID":[1]}],"Reason":3}}'
    )
    r = parse_querylog_line(odd)
    assert (r.filter_id, r.rule, r.upstream, r.answers, r.blocked) == (None, "{'a': 1}", "5", None, True)
    assert parse_querylog_line(odd.replace('"FilterListID":[1]', '"FilterListID":true')).filter_id is None
    no_result = parse_querylog_line('{"T":"2026-10-26T09:14:37Z","QH":"x","IP":"1.2.3.4","Result":5}')
    assert (no_result.blocked, no_result.reason, no_result.rule) == (False, "NotFilteredNotFound", None)
    listed = parse_querylog_line('{"T":"2026-10-26T09:14:37Z","QH":"x","Result":{"Reason":[3]}}')
    assert (listed.blocked, listed.reason) == (False, "[3]")


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


def test_user_rules_from_yaml_in_both_indentations_and_unquoted():
    rules = ["@@||us.lgtvsdp.com^", "||alphonso.tv^", "||ngfts.lge.com^$dnsrewrite=10.10.10.1"]
    assert user_rules_from_yaml(YAML) == rules
    # PyYAML's own output (what `tvgw adguard apply` writes) has no indent under the key
    flat = YAML.replace("  - ", "- ")
    assert user_rules_from_yaml(flat) == rules
    assert user_rules_from_yaml("user_rules:\n- example.org\n- '||x^'\n") == ["example.org", "||x^"]
    assert user_rules_from_yaml("http:\n  address: 1\n") == []  # readable, genuinely empty
    assert user_rules_from_yaml("user_rules: [\n") is None  # unreadable: unknown, not empty
    assert user_rules_from_yaml("- just a list\n") is None


def test_blocked_follows_the_reason_code_not_the_isfiltered_flag():
    rewritten = BLOCKED.replace('"Reason":3,"IsFiltered":true', '"Reason":11,"IsFiltered":true')
    r = parse_querylog_line(rewritten)
    assert r.blocked is False and r.reason == "RewrittenRule"
    service = BLOCKED.replace('"Reason":3,"IsFiltered":true', '"Reason":8')
    assert parse_querylog_line(service).blocked is True
    legacy = BLOCKED.replace('"Reason":3,"IsFiltered":true', '"IsFiltered":true').replace(',"Reason"', "")
    assert parse_querylog_line(legacy).blocked is True  # no numeric reason: fall back to the flag


def test_elapsed_as_text_or_garbage_does_not_raise():
    assert parse_querylog_line(BLOCKED.replace('"Elapsed":264779', '"Elapsed":"264779"')).elapsed_ms > 0
    assert parse_querylog_line(BLOCKED.replace('"Elapsed":264779', '"Elapsed":"soon"')).elapsed_ms == 0
    assert parse_querylog_line(BLOCKED.replace('"Elapsed":264779', '"Elapsed":null')).elapsed_ms == 0
