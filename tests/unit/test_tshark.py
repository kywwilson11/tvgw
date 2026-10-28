"""tshark -T fields rows -> TLS hellos and HTTP requests; `extract` against a scripted tshark."""

import os
import shutil
import subprocess
import types

import pytest

from tvgw import tshark
from tvgw.tshark import AGG, FIELDS, HttpRequest, Syn, TlsHello, command, parse_row


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
                "http.request.method": f"GET{AGG}GET",
                "http.host": f"a.com{AGG}b.com",
                "http.request.uri": f"/x?a=1,2{AGG}/2",
                "http.user_agent": "ua",
            }
        )
    )
    assert [(r.host, r.uri) for r in out] == [("a.com", "/x?a=1,2"), ("b.com", "/2")]


def test_uneven_pipeline_keeps_first_request_only():
    out = parse_row(
        row(
            **{
                "frame.time_epoch": "2",
                "ip.src": "s",
                "ip.dst": "d",
                "http.request.method": f"GET{AGG}POST",
                "http.host": "a.com",
                "http.request.uri": f"/1{AGG}/2",
                "http.user_agent": "ua",
            }
        )
    )
    assert len(out) == 1 and out[0].host == "a.com" and out[0].method == "GET"


def test_rows_with_neither_sni_nor_method_or_bad_fields_are_dropped():
    assert parse_row(row(**{"frame.time_epoch": "3", "ip.src": "s", "ip.dst": "d"})) == []
    assert parse_row("too\tfew\tfields") == []
    assert parse_row(row(**{"frame.time_epoch": "x", "tls.handshake.extensions_server_name": "a"})) == []


def test_command_lists_every_field_in_order_and_can_drop_privileges():
    cmd = command("/tmp/a.pcap")
    assert cmd[:3] == ["tshark", "-r", "/tmp/a.pcap"]
    assert [cmd[i + 1] for i, x in enumerate(cmd) if x == "-e"] == list(FIELDS)
    assert f"aggregator={AGG}" in cmd
    low = command("/tmp/a.pcap", unprivileged=True)
    assert low[0] == "setpriv" and "--reuid=nobody" in low and low[low.index("--") + 1] == "tshark"


def test_http_bodies_are_not_reassembled():
    """The capture keeps the TV's port-80 requests whole; only the request line and headers are read,
    so their bodies must not be held in memory for reassembly."""
    for cmd in (command("/tmp/a.pcap"), command("/tmp/a.pcap", unprivileged=True)):
        assert cmd[cmd.index("-o") + 1] == "http.desegment_body:FALSE"


def test_syn_rows_and_flag_formats():
    syn = parse_row(
        row(
            **{
                "frame.time_epoch": "4",
                "ip.src": "10.10.10.17",
                "tcp.srcport": "40000",
                "ip.dst": "192.168.8.69",
                "tcp.dstport": "80",
                "tcp.flags": "0x0002",
            }
        )
    )
    assert syn == [Syn(4.0, "10.10.10.17", 40000, "192.168.8.69", 80)]
    synack = row(**{"frame.time_epoch": "4", "ip.src": "s", "ip.dst": "d", "tcp.flags": "0x0012"})
    assert parse_row(synack) == []
    ecn_syn = row(**{"frame.time_epoch": "4", "ip.src": "s", "ip.dst": "d", "tcp.flags": "0x00c2"})
    assert len(parse_row(ecn_syn)) == 1
    assert (
        parse_row(row(**{"frame.time_epoch": "4", "ip.src": "s", "ip.dst": "d", "tcp.flags": "junk"})) == []
    )


def test_quic_hello_uses_udp_ports_and_bad_ports_become_zero():
    quic = parse_row(
        row(
            **{
                "frame.time_epoch": "5",
                "ip.src": "10.10.10.17",
                "ip.dst": "1.2.3.4",
                "udp.srcport": "50000",
                "udp.dstport": "443",
                "tls.handshake.extensions_server_name": "www.youtube.com",
            }
        )
    )
    assert quic == [TlsHello(5.0, "10.10.10.17", 50000, "1.2.3.4", 443, "www.youtube.com")]
    odd = row(
        **{
            "frame.time_epoch": "5",
            "ip.src": "s",
            "ip.dst": "d",
            "tcp.srcport": "x",
            "tcp.dstport": "",
            "tls.handshake.extensions_server_name": "a.b",
        }
    )
    assert parse_row(odd)[0].sport == 0


def test_extract_distinguishes_cut_short_from_a_file_it_could_not_open(monkeypatch, tmp_path):
    """Both exit 2. A finished hourly pcap is 'cut short' (fine); a permission error must raise, or the
    pcap is marked done with zero rows (this happened in production on 2026-10-27)."""
    import subprocess
    import types

    from tvgw import tshark

    def fake_run(cmd, **kw):
        return fake_run.result

    monkeypatch.setattr(subprocess, "run", fake_run)
    fake_run.result = types.SimpleNamespace(
        returncode=2, stdout="", stderr="appears to have been cut short in the middle of a packet"
    )
    assert tshark.extract(str(tmp_path / "a.pcap"), unprivileged=False) == []
    fake_run.result = types.SimpleNamespace(
        returncode=2, stdout="", stderr='You don\'t have permission to read the file "a.pcap".'
    )
    try:
        tshark.extract(str(tmp_path / "a.pcap"), unprivileged=False)
    except RuntimeError as e:
        assert "permission" in str(e)
    else:
        raise AssertionError("a file tshark could not open must not look like an empty capture")
    fake_run.result = types.SimpleNamespace(returncode=0, stdout="", stderr="")
    assert tshark.extract(str(tmp_path / "a.pcap"), unprivileged=False) == []


def scripted_tshark(monkeypatch, returncode=0, stdout="", stderr=""):
    """Replace subprocess.run; returns the list every call's (argv, kwargs) is appended to."""
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_extract_frames_rows_on_newline_only_and_rejects_a_shifted_row(monkeypatch):
    """A form feed inside a URI is one row (str.splitlines would make two and lose both); a tab inside
    a URI shifts every later column, so that row is dropped and the next one still lands."""
    hello = row(
        **{
            "frame.time_epoch": "1",
            "ip.src": "s",
            "ip.dst": "d",
            "tls.handshake.extensions_server_name": "a.example",
        }
    )
    syn = row(**{"frame.time_epoch": "2", "ip.src": "s", "ip.dst": "d", "tcp.flags": "0x0002"})
    http = {
        "frame.time_epoch": "3",
        "ip.src": "s",
        "ip.dst": "d",
        "http.request.method": "GET",
        "http.host": "h",
    }
    form_feed = row(**http, **{"http.request.uri": "/a\x0cb"})
    tabbed = row(**http, **{"http.request.uri": "/a\tb"})
    stdout = "\n".join([hello, syn, tabbed, form_feed, "partial\tli"])
    calls = scripted_tshark(monkeypatch, returncode=2, stdout=stdout, stderr="appears to have been cut short")
    out = tshark.extract("/x.pcap", unprivileged=False)
    assert [type(r) for r in out] == [TlsHello, Syn, HttpRequest] and out[2].uri == "/a\x0cb"
    ((cmd, kw),) = calls
    assert cmd[0] == "tshark" and (kw["encoding"], kw["errors"]) == ("utf-8", "replace")


def test_a_tab_inside_the_server_name_yields_no_row():
    assert (
        parse_row(
            row(
                **{
                    "frame.time_epoch": "1",
                    "ip.src": "s",
                    "ip.dst": "d",
                    "tls.handshake.extensions_server_name": "a\tb",
                }
            )
        )
        == []
    )


def test_names_are_cut_at_the_longest_a_hostname_can_be():
    (hello,) = parse_row(
        row(
            **{
                "frame.time_epoch": "1",
                "ip.src": "s",
                "ip.dst": "d",
                "tls.handshake.extensions_server_name": "a" * 70_000,
            }
        )
    )
    (req,) = parse_row(
        row(
            **{
                "frame.time_epoch": "1",
                "ip.src": "s",
                "ip.dst": "d",
                "http.request.method": "GET",
                "http.host": "h" * 70_000,
                "http.request.uri": "/",
            }
        )
    )
    assert len(hello.sni) == len(req.host) == 255


@pytest.mark.parametrize(
    ("euid", "setpriv", "first_word"),
    [(0, "/usr/bin/setpriv", "setpriv"), (1000, "/usr/bin/setpriv", "tshark"), (1000, None, "tshark")],
)
def test_privileges_are_dropped_exactly_when_running_as_root(monkeypatch, euid, setpriv, first_word):
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    monkeypatch.setattr(shutil, "which", lambda name: setpriv)
    calls = scripted_tshark(monkeypatch)
    assert tshark.extract("/x.pcap") == []
    assert calls[0][0][0] == first_word


def test_root_without_setpriv_refuses_to_run_tshark(monkeypatch):
    """Fail closed: the dissectors parse packets from the TV and the internet, so a missing setpriv is
    one ingest warning per hour, not a silent run as root."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    calls = scripted_tshark(monkeypatch)
    with pytest.raises(RuntimeError, match="setpriv not found"):
        tshark.extract("/x.pcap")
    assert calls == []


def test_ech_canary_reads_the_extension_types_in_decimal_or_hex():
    base = {
        "frame.time_epoch": "1792976437.0",
        "ip.src": "10.10.10.17",
        "tcp.srcport": "37082",
        "ip.dst": "45.57.91.1",
        "tcp.dstport": "443",
        "tls.handshake.extensions_server_name": "public.example",
    }
    plain = parse_row(row(**base, **{"tls.handshake.extension.type": f"0{AGG}10{AGG}16"}))
    assert plain[0].ech is False
    for exts in (f"0{AGG}65037{AGG}16", f"0x0000{AGG}0xfe0d"):
        (hello,) = parse_row(row(**base, **{"tls.handshake.extension.type": exts}))
        assert hello.ech is True and hello.sni == "public.example"
