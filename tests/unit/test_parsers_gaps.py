"""Boundary and default behaviours of the parsers (dnsmsg, conntrack, logtail, tshark, adguard, profile, db)."""

import os
import struct

import pytest

from tvgw import adguard, db, logtail, profile
from tvgw.conntrack import parse_flow
from tvgw.dnsmsg import DnsFormatError, answers_text, decode_answers, read_name
from tvgw.logtail import TailState, read_new_lines
from tvgw.tshark import FIELDS, command, parse_row

HDR = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)  # one question, one answer
Q = b"\x03foo\x03com\x00" + struct.pack(">HH", 1, 1)


def rr(rtype, rdata, ttl=30, name=b"\xc0\x0c"):
    return name + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


# ---- dnsmsg ---------------------------------------------------------------------------------------------
def pointer_chain(hops):
    """A name at offset 12 reached through `hops` backward pointers; returns (msg, offset of the last one)."""
    msg = bytearray(12) + b"\x03foo\x00"
    last = 12
    for _ in range(hops):
        off = len(msg)
        msg += struct.pack(">H", 0xC000 | last)
        last = off
    return bytes(msg), last


def test_pointer_chain_limit_is_64_hops():
    msg, last = pointer_chain(64)
    assert read_name(msg, last) == ("foo", last + 2)
    msg, last = pointer_chain(65)
    with pytest.raises(DnsFormatError, match=r"^pointer loop$"):
        read_name(msg, last)


def test_forward_pointer_is_rejected_even_when_it_would_resolve():
    msg = bytes(12) + b"\xc0\x0e" + b"\x03foo\x00"  # points ahead, at a perfectly good name
    with pytest.raises(DnsFormatError, match=r"^pointer loop$"):
        read_name(msg, 12)


@pytest.mark.parametrize(
    "target", [300, 600]
)  # pointer high byte 0xC1 / 0xC2: offsets past the first 256 bytes
def test_pointer_to_a_far_offset(target):
    msg = bytearray(target + 40)
    msg[target : target + 9] = b"\x03foo\x03com\x00"
    msg[target + 20 : target + 22] = struct.pack(">H", 0xC000 | target)
    assert read_name(bytes(msg), target + 20) == ("foo.com", target + 22)


def test_non_ascii_label_is_replaced_not_fatal():
    assert read_name(bytes(12) + b"\x03f\xffo\x00", 12)[0] == "f\ufffdo"


@pytest.mark.parametrize(
    ("msg", "text"),
    [
        (bytes(12) + b"\x03foo", "truncated name"),
        (bytes(12) + b"\xc0", "truncated pointer"),  # lone first byte of a pointer at the very end
    ],
)
def test_read_name_truncation_messages(msg, text):
    with pytest.raises(DnsFormatError, match=rf"^{text}$"):
        read_name(msg, 12)


def test_header_only_message_is_valid_and_one_byte_short_is_not():
    assert decode_answers(bytes(12)) == []
    with pytest.raises(DnsFormatError, match=r"^short header$"):
        decode_answers(bytes(11))


def test_answer_count_larger_than_the_data_is_an_error():
    with pytest.raises(DnsFormatError):
        decode_answers(struct.pack(">HHHHHH", 1, 0x8180, 0, 40000, 0, 0) + b"\x00")


def test_record_header_ending_exactly_at_the_message_end_is_complete():
    msg = HDR + Q + rr(1, b"")  # an A record with an empty rdata is skipped, not "truncated"
    assert decode_answers(msg) == []
    with pytest.raises(DnsFormatError, match=r"^truncated record$"):
        decode_answers(msg[:-1])
    with pytest.raises(DnsFormatError, match=r"^truncated rdata$"):
        decode_answers(HDR + Q + rr(1, b"\x01\x02\x03\x04")[:-2])


def test_ttl_and_value_formats_for_each_record_type():
    aaaa = bytes.fromhex("2607f8b0400980b0") + bytes(6) + b"\x20\x0e"
    cname = b"\x03bar\x03com\x00"
    msg = (
        struct.pack(">HHHHHH", 1, 0x8180, 1, 3, 0, 0)
        + Q
        + rr(1, bytes([35, 166, 189, 68]), ttl=0xFFFFFFFF)
        + rr(28, aaaa, ttl=7)
        + rr(5, cname, ttl=9)
    )
    a, aaaa_ans, c = decode_answers(msg)
    assert (a.rtype, a.value, a.ttl) == ("A", "35.166.189.68", 0xFFFFFFFF)  # unsigned TTL
    assert (aaaa_ans.value, aaaa_ans.ttl) == ("2607:f8b0:4009:80b0:0:0:0:200e", 7)
    assert (c.rtype, c.value, c.ttl) == ("CNAME", "bar.com", 9)
    assert answers_text(msg) == "A:35.166.189.68,AAAA:2607:f8b0:4009:80b0:0:0:0:200e,CNAME:bar.com"


@pytest.mark.parametrize(("rtype", "rdlen"), [(16, 16), (1, 16), (28, 4), (1, 3)])
def test_records_with_the_wrong_type_or_length_are_skipped(rtype, rdlen):
    assert decode_answers(HDR + Q + rr(rtype, bytes(rdlen))) == []


# ---- conntrack ----------------------------------------------------------------------------------------------
UDP_ASSURED = (
    "[1792977952.5]\t[DESTROY] ipv4     2 udp      17 src=10.10.10.17 dst=1.1.1.1 sport=1 dport=2 packets=1 bytes=2 "
    "src=1.1.1.1 dst=10.10.10.17 sport=2 dport=1 packets=3 bytes=4 [ASSURED] delta-time=5"
)


def test_bracketed_flags_never_become_the_state():
    f = parse_flow(UDP_ASSURED)
    assert f.state is None and (f.pkts_down, f.bytes_down) == (3, 4)


def test_ipv6_flow():
    line = (
        "[1792977952.5]\t[DESTROY] ipv6     10 tcp      6 TIME_WAIT src=fd00::17 dst=2607:f8b0::1 sport=5 dport=443 "
        "packets=2 bytes=100 src=2607:f8b0::1 dst=fd00::17 sport=443 dport=5 packets=3 bytes=200 [ASSURED] delta-time=2"
    )
    f = parse_flow(line)
    assert (f.src, f.dst, f.dport, f.bytes_up, f.bytes_down, f.state) == (
        "fd00::17",
        "2607:f8b0::1",
        443,
        100,
        200,
        "TIME_WAIT",
    )


def test_missing_or_bad_duration_means_zero_length_flow():
    base = UDP_ASSURED.rsplit(" delta-time", 1)[0]
    for line in (base, base + " delta-time=abc"):
        f = parse_flow(line)
        assert f.t_start == f.t_end == 1792977952.5


@pytest.mark.parametrize(
    "line",
    [
        "1792977952.5 [DESTROY] ipv4 2 udp 17 src=1.1.1.1 dst=2.2.2.2 sport=1 dport=2 packets=1 bytes=2",  # no [ts]
        "[1.0] [DESTROY] ipv4 2 udp 17 src=1.1.1.1 sport=1 dport=2 packets=1 bytes=2",  # source but no destination
    ],
)
def test_malformed_lines_return_none(line):
    assert parse_flow(line) is None


# ---- logtail --------------------------------------------------------------------------------------------------
def test_trailing_whitespace_and_blank_lines_are_preserved_except_the_newline(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"EXIT X\n\n tail \r\n")
    assert read_new_lines(str(p), TailState())[0] == ["EXIT X", "", " tail \r"]


def test_stale_dot1_from_an_older_rotation_is_not_replayed(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"one\ntwo\n")
    _, st = read_new_lines(str(p), TailState())
    os.rename(p, tmp_path / "a.log.2")  # we missed one rotation: ours is now .2
    (tmp_path / "a.log.1").write_bytes(b"BBBBBBBB\nBBBBBBBB\n")  # a different file's content
    p.write_bytes(b"new\n")
    lines, _ = read_new_lines(str(p), st)
    assert lines == ["new"]


def test_dot1_that_vanishes_between_exists_and_stat(tmp_path, monkeypatch):
    p = tmp_path / "a.log"
    p.write_bytes(b"aaaa\nbbbb\n")
    _, st = read_new_lines(str(p), TailState())
    p.write_bytes(b"x\n")
    monkeypatch.setattr(logtail.os.path, "exists", lambda path: True)  # but a.log.1 does not exist
    assert read_new_lines(str(p), st)[0] == ["x"]


@pytest.mark.parametrize(
    ("content", "state", "lines", "offset"),
    [
        (b"abcd\n", TailState(None, 5), [], 5),  # nothing new, nothing replayed
        (b"ab\n", TailState(None, 40), ["ab"], 3),  # shorter than the stored offset: start over
    ],
)
def test_state_without_an_inode(tmp_path, content, state, lines, offset):
    p = tmp_path / "a.log"
    p.write_bytes(content)
    got, st = read_new_lines(str(p), state)
    assert (got, st.offset) == (lines, offset)


# ---- tshark ---------------------------------------------------------------------------------------------------
def test_command_is_exactly_the_documented_invocation():
    cmd = command("/x.pcap")
    assert cmd[:8] == ["tshark", "-r", "/x.pcap", "-n", "-Y", cmd[5], "-T", "fields"]
    assert cmd[5].startswith("(tls.handshake.type == 1")


def row(**kw):
    vals = dict.fromkeys(FIELDS, "")
    vals.update({"frame.time_epoch": "1.0", "ip.src": "s", "ip.dst": "d", **kw})
    return "\t".join(vals[f] for f in FIELDS)


def test_row_parsing_trailing_newline_and_empty_ports():
    (hello,) = parse_row(row(**{"tls.handshake.extensions_server_name": "A.example"}) + "\n")
    assert (hello.sni, hello.sport, hello.dport) == ("a.example", 0, 0)
    (req,) = parse_row(
        row(
            **{
                "http.request.method": "GET",
                "http.host": "h",
                "http.request.uri": "/",
                "http.user_agent": "agent X",
            }
        )
        + "\n"
    )
    assert req.user_agent == "agent X"  # the newline goes, a trailing X stays


def test_two_methods_hosts_but_one_uri_is_one_request():
    out = parse_row(
        row(**{"http.request.method": "GET,GET", "http.host": "a.com,b.com", "http.request.uri": "/1"})
    )
    assert len(out) == 1


def test_three_methods_but_two_hosts_is_one_request():
    out = parse_row(
        row(
            **{
                "http.request.method": "GET,GET,GET",
                "http.host": "a.com,b.com",
                "http.request.uri": "/1,/2,/3",
            }
        )
    )
    assert len(out) == 1


@pytest.mark.xfail(
    strict=True, reason="uneven pipelines keep the raw comma-joined host and uri instead of the first pair"
)
def test_uneven_pipeline_uses_the_first_host_and_uri():
    (req,) = parse_row(
        row(**{"http.request.method": "GET,POST", "http.host": "A.com,b.com", "http.request.uri": "/1"})
    )
    assert (req.method, req.host, req.uri) == ("GET", "a.com", "/1")


# ---- adguard ---------------------------------------------------------------------------------------------------
def test_fraction_digits_are_left_aligned():
    base = adguard.parse_time("2026-10-26T14:14:37Z")
    assert adguard.parse_time("2026-10-26T14:14:37.5Z") - base == pytest.approx(0.5, abs=1e-6)
    assert adguard.parse_time("2026-10-26T14:14:37.123456789Z") - base == pytest.approx(0.123456, abs=1e-6)


def test_naive_timestamps_are_local_time():
    assert adguard.parse_time("2026-10-26 09:14:37") == adguard.parse_time("2026-10-26T09:14:37-05:00")


def test_record_defaults_for_missing_fields():
    r = adguard.parse_querylog_line('{"T":"2026-10-26T09:14:37Z"}')
    assert (r.client, r.qname, r.qtype, r.elapsed_ms, r.reason, r.upstream) == (
        "",
        "",
        "",
        0.0,
        "NotFilteredNotFound",
        None,
    )


YAML_EMPTY = "http:\n  a: 1\nuser_rules:\ndhcp:\n  enabled: false\n"
YAML_LAST = "http:\n  a: 1\nuser_rules:\n  - 'x'\n  - 'y'\n"


def test_replace_user_rules_exact_output():
    assert (
        adguard.replace_user_rules(YAML_EMPTY, ["||a^"])
        == "http:\n  a: 1\nuser_rules:\n  - '||a^'\ndhcp:\n  enabled: false\n"
    )
    assert (
        adguard.replace_user_rules(YAML_EMPTY, []) == YAML_EMPTY
    )  # an already empty list keeps the next key
    assert (
        adguard.replace_user_rules(YAML_LAST, ["z"]) == "http:\n  a: 1\nuser_rules:\n  - 'z'\n"
    )  # list runs to EOF
    assert adguard.replace_user_rules(YAML_LAST, []) == "http:\n  a: 1\nuser_rules:\n"


@pytest.mark.xfail(
    strict=True, reason="AdGuard writes an empty list as `user_rules: []`; replace appends items under it"
)
def test_replace_user_rules_on_flow_style_empty_list():
    out = adguard.replace_user_rules("user_rules: []\ndhcp:\n  enabled: false\n", ["||a^"])
    assert out == "user_rules:\n  - '||a^'\ndhcp:\n  enabled: false\n"


# ---- profile --------------------------------------------------------------------------------------------------------
def test_from_dict_defaults_and_shape():
    p = profile.from_dict({"categories": {"strip_prefixes": ["xx."], "A": ["a.com"], "B": ["b.com"]}})
    assert (p.name, p.vendor, p.description) == ("unnamed", "", "")
    named = profile.from_dict({"profile": {"name": "n", "vendor": "v", "description": "d"}})
    assert (named.name, named.vendor, named.description) == ("n", "v", "d")
    assert p.category_order == ("A", "B") and p.strip_prefixes == ("xx.",)  # strip_prefixes is not a category
    assert p.url_filter is None and p.must_allow == {} and p.adguard_filters == ()
    assert p.categorize("xx.unlisted.org") == "Other"


def test_url_filter_hosts_are_lowercased():
    p = profile.from_dict({"url_filter": {"hosts": ["NGFTS.lge.com"], "block_regex": "x"}})
    assert p.url_filter.hosts == ("ngfts.lge.com",) and p.url_filter.blocks("/X")


def test_trailing_dot_and_case_are_normalised_before_matching():
    p = profile.from_dict({"categories": {"ACR": ["alphonso.tv"]}})
    assert p.categorize("PROV.Alphonso.TV.") == "ACR"


def test_catch_all_pattern_and_tie_break_by_file_order():
    p = profile.from_dict({"categories": {"First": ["x.com"], "Second": ["x.com"], "Rest": ["*"]}})
    assert p.categorize("x.com") == "First"  # equal-length patterns: the earlier category wins
    assert p.categorize("anything.org") == "Rest"


def test_bundled_profile_name_wins_over_a_same_named_file_in_cwd(tmp_path, monkeypatch):
    (tmp_path / "lg-webos").write_text("not toml at all {{{")
    monkeypatch.chdir(tmp_path)
    assert profile.load("lg-webos").vendor == "LG"


# ---- db ---------------------------------------------------------------------------------------------------------------
def test_connect_settings(tmp_path):
    path = str(tmp_path / "s.db")
    w = db.connect(path)
    assert w.execute("PRAGMA busy_timeout").fetchone()[0] == 60000  # readers must outwait the hourly writer
    assert w.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    assert db.get_meta(w, "schema") == str(db.SCHEMA_VERSION)
    w.commit()
    r = db.connect(path, readonly=True)
    assert r.execute("PRAGMA busy_timeout").fetchone()[0] == 60000
    assert db.get_meta(r, "missing") is None
