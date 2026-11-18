"""(bounds) Properties of the parsers that read hostile bytes (design decision 107): each one's contract
over the inputs hypothesis makes, at the gate's 300 examples, derandomized so a failure reproduces.

The contracts are the ones each module states: a parser of the TV's or the internet's bytes never
raises, or raises only the error its docstring names, and what it returns keeps its shape. Three
properties pin decision 107's bounds: a limited DNS decode reads a prefix of the answers; a query-log
line between two lookups never stops them being stored, nor the cursor moving past it; and tshark's
rows read as it prints them are the rows its whole output gave. The properties of the TV client's message
handlers and of `discover.parse_neigh` come with the changes that make them hold. Every `@example` is an
input that broke a contract before decision 107."""

import contextlib
import ipaddress
import json
import shutil
import struct
import tempfile
from pathlib import Path
from unittest import mock

import pytest

pytest.importorskip("hypothesis")  # the dev extras carry it
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st
from test_tshark import printed_whole

from tvgw import (
    adguard,
    clienthello,
    conntrack,
    db,
    discover,
    dnsmsg,
    flowlog,
    ingest,
    lgwebos,
    nfnl,
    scrub,
    tizen,
    tshark,
    tvlive,
    web,
    webauth,
)
from tvgw.config import Settings

GATE = settings(
    max_examples=300,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large, HealthCheck.filter_too_much],
)
# a property that starts a process or opens a store per example: fewer of them, the same strategies
SLOW = settings(GATE, max_examples=60)
TV = "10.10.10.17"


# ---- dnsmsg -------------------------------------------------------------------------------------------------
label = st.binary(min_size=1, max_size=20)


def name_bytes(labels: list[bytes], ptr: int | None = None) -> bytes:
    return b"".join(bytes([len(x)]) + x for x in labels) + (
        struct.pack(">H", 0xC000 | ptr) if ptr is not None else b"\x00"
    )


@st.composite
def dns_messages(draw) -> bytes:
    """A message of up to 8 answers of the types the decoder reads and two it skips, with pointers, lying
    lengths and counts, and a few flipped bytes."""
    msg = struct.pack(">HHHHHH", draw(st.integers(0, 65535)), 0x8180, draw(st.integers(0, 3)), 0, 0, 0)
    msg += name_bytes(draw(st.lists(label, max_size=5))) + struct.pack(">HH", 1, 1)
    n = draw(st.integers(0, 8))
    for _ in range(n):
        msg += name_bytes(draw(st.lists(label, max_size=3)), draw(st.none() | st.integers(0, 80)))
        rd = draw(
            st.binary(max_size=40)
            | st.just(b"\x01\x02\x03\x04")
            | st.builds(name_bytes, st.lists(label, max_size=3), st.none() | st.integers(0, 80))
        )
        rdlen = draw(st.just(len(rd)) | st.integers(0, 60))
        rtype = draw(st.sampled_from([1, 5, 28, 16, 65]))
        msg += struct.pack(">HHIH", rtype, 1, draw(st.integers(0, 2**32 - 1)), rdlen) + rd
    msg = bytearray(msg)
    struct.pack_into(">H", msg, 6, draw(st.just(n) | st.integers(0, 65535)))
    for _ in range(draw(st.integers(0, 4))):
        msg[draw(st.integers(0, len(msg) - 1))] = draw(st.integers(0, 255))
    return bytes(msg)


ANY_DNS = st.binary(max_size=600) | dns_messages()


@GATE
@given(ANY_DNS)
def test_the_dns_readers_raise_only_a_format_error_and_agree_on_the_a_records(msg):
    try:
        found = dnsmsg.decode_answers(msg)
    except (dnsmsg.DnsFormatError, struct.error):
        found = None
    text = dnsmsg.answers_text(msg)
    assert text is None or isinstance(text, str)
    assert dnsmsg.qname(msg) is None or isinstance(dnsmsg.qname(msg), str)
    assert dnsmsg.rcode(msg) >= -1
    try:
        a = dnsmsg.a_rdata(msg)
    except dnsmsg.DnsFormatError:
        a = None
    if found is not None:  # the in-path filler's reader takes the same A records as the full decoder
        assert a is not None
        assert [".".join(map(str, x)) for x in a] == [x.value for x in found if x.rtype == "A"]
        for x in found:  # and a label can never forge the stored `A:1.2.3.4,CNAME:x` grammar
            assert x.rtype != "CNAME" or all(32 < ord(c) < 127 and c not in ",:" for c in x.value)


@GATE
@given(st.text(max_size=400))
def test_answers_text_reads_base64_text_or_returns_none(s):
    assert dnsmsg.answers_text(s) is None or isinstance(dnsmsg.answers_text(s), str)


@GATE
@given(ANY_DNS, st.integers(0, 10))
def test_a_limited_decode_reads_a_prefix_of_the_answers_and_fails_only_where_a_whole_one_does(msg, limit):
    """(bounds) The store's reader stops at adguard.ANSWER_RECORDS: what it keeps is what a whole decode
    has first, and a message it cannot read past its limit is one a whole decode cannot read either."""
    try:
        cut = dnsmsg.decode_answers(msg, limit=limit)
    except (dnsmsg.DnsFormatError, struct.error):
        with pytest.raises((dnsmsg.DnsFormatError, struct.error)):
            dnsmsg.decode_answers(msg)
        return
    try:
        whole = dnsmsg.decode_answers(msg)
    except (dnsmsg.DnsFormatError, struct.error):
        return  # the fault lies past the limit, which is never read
    assert whole[: len(cut)] == cut and len(cut) <= limit
    if struct.unpack_from(">H", msg, 6)[0] <= limit:  # a decoded message has its 12-byte header
        assert cut == whole


# ---- clienthello --------------------------------------------------------------------------------------------
def vec(n: int, data: bytes) -> bytes:
    return len(data).to_bytes(n, "big") + data


@st.composite
def hellos(draw) -> bytes:
    """A ClientHello record with a name, ALPN, signature and version lists among other extensions, then a
    few flipped bytes and a cut anywhere."""
    ciphers = b"".join(
        draw(st.integers(0, 65535)).to_bytes(2, "big") for _ in range(draw(st.integers(0, 40)))
    )
    exts = b""
    for _ in range(draw(st.integers(0, 12))):
        etype = draw(st.sampled_from([0, 16, 13, 43, 0xFE0D, 10, 11, 0x0A0A, 51, 65281]))
        if etype == 0:
            names = st.tuples(st.integers(0, 1), st.binary(max_size=40)).map(
                lambda p: bytes([p[0]]) + vec(2, p[1])
            )
            body = vec(2, b"".join(draw(st.lists(names, max_size=3))))
        elif etype == 16:
            body = vec(2, b"".join(vec(1, p) for p in draw(st.lists(st.binary(max_size=10), max_size=4))))
        elif etype == 13:
            body = vec(2, draw(st.binary(max_size=30)))
        elif etype == 43:
            body = vec(1, draw(st.binary(max_size=12)))
        else:
            body = draw(st.binary(max_size=30))
        exts += etype.to_bytes(2, "big") + vec(2, body)
    body = draw(st.integers(0, 65535)).to_bytes(2, "big") + bytes(32) + vec(1, draw(st.binary(max_size=32)))
    body += vec(2, ciphers) + vec(1, b"\x00") + (vec(2, exts) if draw(st.booleans()) else b"")
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = bytearray(b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs)
    for _ in range(draw(st.integers(0, 4))):
        rec[draw(st.integers(0, len(rec) - 1))] = draw(st.integers(0, 255))
    return bytes(rec[: draw(st.just(len(rec)) | st.integers(0, len(rec)))])


@GATE
@given(st.binary(max_size=400) | hellos())
def test_a_hello_never_raises_and_its_fingerprint_keeps_its_shape(data):
    for h in (
        clienthello.parse_record(data),
        clienthello.parse_handshake(data),
        clienthello.parse_handshake(data[5:]),
    ):
        if h is not None:
            assert len(h.sni) <= 255
            assert all(isinstance(v, tuple) for v in (h.ciphers, h.extensions, h.alpn, h.sig_algs))
            j = clienthello.ja4(clienthello.from_hello(h))
            assert j.count("_") == 2 and j.isascii() and len(j) == 36
            clienthello.ja4_r(clienthello.from_hello(h))


# ---- conntrack ----------------------------------------------------------------------------------------------
FLOW = (
    "[1792977952.120409]\t[DESTROY] ipv4     2 tcp      6 TIME_WAIT src=10.10.10.17 dst=192.0.2.1 sport=58998 "
    "dport=443 packets=18 bytes=2259 src=192.0.2.1 dst=198.51.100.48 sport=443 dport=58998 packets=23 "
    "bytes=10742 [ASSURED] delta-time=360"
)
ODD_TOKENS = [
    "bytes=99999999999999999999", "delta-time=nan", "delta-time=-1", "delta-time=1e400", "[nan]", "[inf]",
    "[1e400]", "ipv6", "9" * 30, "sport=²", "packets=" + "9" * 5000,
]  # fmt: skip
token = st.sampled_from(FLOW.split()) | st.text(max_size=12) | st.sampled_from(ODD_TOKENS)


@GATE
@given(st.text(max_size=300) | st.lists(token, max_size=30).map(" ".join))
def test_a_flow_line_raises_only_value_error_and_stores_only_what_sqlite_binds(line):
    try:
        f = conntrack.parse_flow(line)
    except ValueError:
        return
    if f is not None:
        assert f.t_start == f.t_start and f.t_end == f.t_end  # never NaN
        assert all(0 <= v < 1 << 63 for v in (f.pkts_up, f.bytes_up, f.pkts_down, f.bytes_down))


# ---- tshark ------------------------------------------------------------------------------------------------
FIELD_VALUES = [
    "1792977952.5", "nan", "inf", TV, "443", "0x0002", "1", "0x0303", "4865\x1f4866", "evil\x1b[2J.example",
    "GET", "GET\x1fPOST", "16:03:01:00:05:01:00:00:01:00", "0xfe0d", "h2\x1fhttp/1.1", "9" * 5000,
    "0x" + "f" * 5000, "\x1f\x1f",
]  # fmt: skip
field = st.just("") | st.text(max_size=30) | st.sampled_from(FIELD_VALUES)
ROW = st.lists(field, min_size=len(tshark.FIELDS), max_size=len(tshark.FIELDS)).map("\t".join)


@GATE
@given(st.text(max_size=400) | ROW)
def test_a_tshark_row_never_raises(line):
    rows = tshark.parse_row(line)
    tshark.dedupe(rows)
    tshark.summary(rows, TV)


printed = st.lists(ROW.map(str.encode) | st.binary(max_size=60), max_size=12)


@SLOW
@given(printed, st.sampled_from([b"\n", b"\r\n", b"\r"]))
def test_rows_read_as_tshark_prints_them_are_the_rows_its_whole_output_gave(rows, eol):
    """(bounds) `extract` reads tshark through a pipe as it prints, never its whole output at once: the
    same bytes, invalid UTF-8 and every newline among them, give the same rows."""
    with tempfile.TemporaryDirectory() as folder:
        out = Path(folder) / "stdout"
        out.write_bytes(eol.join(rows))
        with mock.patch.object(tshark, "command", lambda pcap, unprivileged, timeout: ["cat", str(out)]):
            assert tshark.extract("/x.pcap", unprivileged=False) == printed_whole(out.read_bytes())


# ---- adguard ------------------------------------------------------------------------------------------------
ODD_LEAVES = [
    "2026-11-01T00:00:00.123456789Z", "2026-11-01T00:00:00+05:30", "0001-01-01T00:00:00", TV, "AAAA",
    10**400, -(10**400), 1e308, 2**70,
]  # fmt: skip
leaf = (
    st.none()
    | st.booleans()
    | st.integers(-(10**30), 10**30)
    | st.floats(allow_nan=True)
    | st.text(max_size=20)
    | st.sampled_from(ODD_LEAVES)
)
json_value = st.recursive(
    leaf,
    lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=8), c, max_size=4),
    max_leaves=12,
)
KEYS = ["T", "QH", "QT", "IP", "Answer", "Result", "Elapsed", "Cached", "Upstream"]
record = st.fixed_dictionaries({}, optional=dict.fromkeys(KEYS, json_value)).map(
    lambda d: (
        {
            **d,
            "Result": {
                "Reason": d["Result"],
                "Rules": [{"Text": d.get("QH"), "FilterListID": d.get("Elapsed")}],
            },
        }
        if "Result" in d and not isinstance(d["Result"], dict)
        else d
    )
)
DEEP = "[" * 100_000
FAR = '{"T":"2026-11-01T00:00:00Z","QH":"a.example","IP":"10.10.10.17","Elapsed":1' + "0" * 400 + "}"


@GATE
@given(st.text(max_size=200) | record.map(json.dumps) | json_value.map(json.dumps))
@example(DEEP)  # RecursionError out of json.loads
@example(FAR)  # OverflowError out of float()
def test_a_query_log_line_raises_only_value_error(line):
    try:
        r = adguard.parse_querylog_line(line)
    except ValueError:
        return
    assert r is None or isinstance(r.t, float)


@GATE
@given(json_value)
@example(10**400)  # OverflowError out of float()
def test_an_api_entry_never_raises(entry):
    adguard.parse_api_entry(entry)
    adguard.parse_api_entry(
        {
            "time": "2026-11-01T00:00:00Z",
            "question": {"name": "a.example"},
            "elapsedMs": entry,
            "rules": [entry],
            "reason": entry,
        }
    )


def lookup(i: int, **fields) -> str:
    return json.dumps({"T": f"2026-11-01T00:00:0{i}Z", "QH": f"n{i}.example", "IP": TV, **fields}) + "\n"


@pytest.fixture(scope="module")
def blank_store(tmp_path_factory) -> Path:
    """An empty store, copied for each example: making the schema anew costs twenty times the copy."""
    path = tmp_path_factory.mktemp("store") / "blank.db"
    db.connect(str(path)).close()
    return path


@SLOW
@given(st.text(max_size=200).filter(lambda s: "\n" not in s) | record.map(json.dumps))
@example(DEEP)
@example(FAR)
@example(lookup(1, QH="n\ud800.example").rstrip("\n"))  # UnicodeEncodeError at the bind
@example(
    lookup(1, Result={"Rules": [{"Text": "x", "FilterListID": 2**70}]}).rstrip("\n")
)  # OverflowError there
def test_any_line_between_two_lookups_leaves_both_stored_and_the_cursor_past_it(blank_store, line):
    """(bounds) One odd line raised out of the dns step, which rolled back its hour and every hour after it."""
    with tempfile.TemporaryDirectory() as folder:
        log = Path(folder) / "querylog.json"
        log.write_text(lookup(0) + line + "\n" + lookup(2), encoding="utf-8")
        store = shutil.copyfile(blank_store, Path(folder) / "t.db")
        s = Settings(tv_ip=TV, db_path=str(store), adguard_querylog=str(log))
        conn = db.connect(s.db_path)
        try:
            ingest.ingest_dns(conn, s, warn=lambda w: None)
            conn.commit()
            names = {q for (q,) in conn.execute("SELECT qname FROM dns")}
            offset = conn.execute("SELECT offset FROM ingest_state WHERE source='adguard'").fetchone()[0]
        finally:
            conn.close()
        assert {"n0.example", "n2.example"} <= names and offset == log.stat().st_size


# ---- the TV's own words, through tvgw's readers ------------------------------------------------------------
KEY = st.sampled_from(
    [
        "id",
        "type",
        "payload",
        "error",
        "state",
        "appId",
        "returnValue",
        "processing",
        "subscribed",
        "errorText",
    ]
)
message = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.text(max_size=12)
    | st.sampled_from(["power", "app", "error", "Active", "com.webos.app.home"]),
    lambda c: st.lists(c, max_size=3) | st.dictionaries(KEY, c, max_size=5),
    max_leaves=10,
)


@GATE
@given(message)
def test_the_tv_readings_value_readers_never_raise(v):
    for read in (lgwebos.power_event, lgwebos.app_event, lgwebos.consent, lgwebos.agreements, lgwebos.paths):
        read(v)
    for read in (lgwebos._hello_fields, lgwebos.clean, lgwebos.country_code, lgwebos.generation_from_release):
        read(v)
    lgwebos.consent({"eulaStatus": v})
    lgwebos.agreements({"eulaInfoNetwork": v})
    lgwebos.paths({"wired": v, "wifi": v, "bluetooth": v})


@GATE
@given(st.binary(max_size=300), st.floats(allow_nan=False, allow_infinity=False, min_value=0, max_value=4e9))
def test_the_attempts_ledger_reads_only_real_times(data, now):
    for t, _who, _keep in tvlive.Ledger._parse(data, now):
        assert t == t and abs(t) != float("inf")


@GATE
@given(st.binary(max_size=300))
def test_the_netlink_decoders_raise_only_their_own_error(data):
    with contextlib.suppress(nfnl.NlError):
        for m in nfnl.messages(data):
            for decode in (nfnl.queue_packet, nfnl.log_packet, nfnl.ack):
                with contextlib.suppress(nfnl.NlError):
                    decode(m)
    with contextlib.suppress(nfnl.NlError):
        nfnl.attrs(data)
    assert isinstance(nfnl.batch_result([data], 1), int)


HTTP_OK = b"HTTP/1.1 200 OK\r\n"


@GATE
@given(
    st.binary(max_size=300)
    | message.map(lambda v: HTTP_OK + b"Content-Type: a\r\n\r\n" + json.dumps(v).encode())
    | st.binary(max_size=80).map(lambda b: HTTP_OK + b"Transfer-Encoding: chunked\r\n\r\n" + b)
)
def test_a_samsung_reply_raises_only_refused(raw):
    tizen._complete(raw)
    try:
        info = tizen.parse(raw)
    except tizen.Refused:
        return
    tizen.is_samsung_tv(info)
    tizen.device_values(info)
    tizen.read("192.0.2.1", get=lambda ip, port: info).lines()
    tizen.identify("192.0.2.1", get=lambda ip, port: info)


DEVICE_KEYS = ["type", "OS", "modelName", "model", "firmwareVersion", "PowerState", "networkType", "ssid",
               "wifiMac", "countryCode", "smartHubAgreement", "FrameTVSupport", "name", "duid"]  # fmt: skip


@GATE
@given(st.dictionaries(st.sampled_from(DEVICE_KEYS), message, max_size=8))
def test_a_samsung_devices_values_are_printable_text(device):
    for v in tizen.device_values({"device": device}).values():
        assert isinstance(v, str) and v.isprintable()


# ---- the gateway's own readers of what devices and the system announce -------------------------------------
@GATE
@given(st.binary(max_size=400), st.text(max_size=400))
def test_the_discovery_parsers_never_raise(b, t):
    discover.ssdp_hint(discover.parse_ssdp(b))
    for read in (
        discover.parse_description,
        discover.parse_leases,
        discover.dhcp_transactions,
        discover.dhcp_names,
    ):
        read(t)
    for read in (discover.vendor_class_hint, discover.hostname_hint, discover.safe_name, discover.announced):
        read(t)
    discover.location_ok(t, "192.0.2.1")


@GATE
@given(st.text(max_size=300))
def test_the_web_pages_small_parsers_never_raise(t):
    webauth.parse_hash(t)
    webauth.check_password(t, t)
    web._cookies(t)
    web.tcp_listeners(t, t, 8443)
    web.fingerprint(t)


@GATE
@given(st.text(max_size=300))
def test_the_flow_loggers_proc_readers_never_raise(t):
    flowlog.parse_proc_netlink(t)
    flowlog.parse_proc_netlink("sk Eth Pid Groups Rmem Wmem Dump Locks Drops Inode\n" + t)
    flowlog._ppid(t)


# ---- scrub --------------------------------------------------------------------------------------------------
SCRUB = scrub.Scrubber(
    "10.10.10.0/24",
    router="198.51.100.1",
    uplink_addrs=["198.51.100.7"],
    hostname="gatewaybox",
    tv_name="LivingRoomTV",
    ssids=["HomeNet"],
    keep=scrub.SHIPPED,
)
AROUND = st.text(alphabet=" ,;:=()[]<>\"'/\\abcxyz\t-_", max_size=6)
TV_NET = ipaddress.ip_network("10.10.10.0/24")
octet = st.integers(0, 255)


@GATE
@given(st.text(max_size=300))
def test_scrub_never_raises(t):
    SCRUB(t)


@GATE
@given(st.tuples(octet, octet, octet, octet).map(lambda o: ipaddress.IPv4Address(bytes(o))), AROUND, AROUND)
def test_a_private_address_outside_the_tv_side_never_survives_scrub(a, before, after):
    kept = (
        a.is_loopback
        or a.is_unspecified
        or a.is_multicast
        or a in TV_NET
        or a == ipaddress.IPv4Address(2**32 - 1)
    )
    if a.is_private and not kept:  # the TV's side stays, and so do addresses that name no device
        assert str(a) not in SCRUB(before + str(a) + after)


@GATE
@given(
    st.binary(min_size=6, max_size=6),
    st.sampled_from([":", "-"]),
    st.booleans(),
    st.sampled_from(["", " ", "=", "mac:", "ether ", "(", "'"]),
    st.sampled_from(["", " ", ")", ",", "'", "\n"]),
)
def test_a_mac_never_survives_scrub(raw, sep, upper, before, after):
    mac = sep.join(f"{b:02x}" for b in raw)
    mac = mac.upper() if upper else mac
    assert mac not in SCRUB(before + mac + after)
