"""tshark -T fields rows -> TLS hellos and HTTP requests."""

from tvgw.tshark import FIELDS, HttpRequest, TlsHello, command, parse_row


def row(**kw):
    vals = {f: "" for f in FIELDS}
    vals.update(kw)
    return "\t".join(vals[f] for f in FIELDS)


def test_tls_hello_row():
    out = parse_row(
        row(
            **{
                "frame.time_epoch": "1792976437.257143000",
                "ip.src": "10.10.10.17",
                "tcp.srcport": "37082",
                "ip.dst": "45.57.91.1",
                "tcp.dstport": "443",
                "tls.handshake.extensions_server_name": "OCC.a.nflxso.net",
            }
        )
    )
    assert out == [TlsHello(1792976437.257143, "10.10.10.17", 37082, "45.57.91.1", 443, "occ.a.nflxso.net")]


def test_http_request_row():
    out = parse_row(
        row(
            **{
                "frame.time_epoch": "1.5",
                "ip.src": "10.10.10.17",
                "ip.dst": "23.5.6.43",
                "http.request.method": "GET",
                "http.host": "NGFTS.lge.com",
                "http.request.uri": "/fts/x?biz_code=MAS",
                "http.user_agent": "Mozilla/5.0 (Web0S)",
            }
        )
    )
    assert out == [
        HttpRequest(
            1.5,
            "10.10.10.17",
            "23.5.6.43",
            "GET",
            "ngfts.lge.com",
            "/fts/x?biz_code=MAS",
            "Mozilla/5.0 (Web0S)",
        )
    ]


def test_pipelined_requests_are_split():
    out = parse_row(
        row(
            **{
                "frame.time_epoch": "2",
                "ip.src": "s",
                "ip.dst": "d",
                "http.request.method": "GET,GET",
                "http.host": "a.com,b.com",
                "http.request.uri": "/1,/2",
                "http.user_agent": "ua",
            }
        )
    )
    assert [(r.host, r.uri) for r in out] == [("a.com", "/1"), ("b.com", "/2")]


def test_uneven_pipeline_keeps_first_request_only():
    out = parse_row(
        row(
            **{
                "frame.time_epoch": "2",
                "ip.src": "s",
                "ip.dst": "d",
                "http.request.method": "GET,POST",
                "http.host": "a.com",
                "http.request.uri": "/1,/2",
                "http.user_agent": "ua",
            }
        )
    )
    assert len(out) == 1 and out[0].host == "a.com" and out[0].method == "GET"


def test_rows_with_neither_sni_nor_method_or_bad_fields_are_dropped():
    assert parse_row(row(**{"frame.time_epoch": "3", "ip.src": "s", "ip.dst": "d"})) == []
    assert parse_row("too\tfew\tfields") == []
    assert parse_row(row(**{"frame.time_epoch": "x", "tls.handshake.extensions_server_name": "a"})) == []


def test_command_lists_every_field_in_order():
    cmd = command("/tmp/a.pcap")
    assert cmd[:3] == ["tshark", "-r", "/tmp/a.pcap"]
    assert [cmd[i + 1] for i, x in enumerate(cmd) if x == "-e"] == list(FIELDS)
