"""tshark -T fields rows -> TLS hellos and HTTP requests; `extract` against a scripted tshark."""

import os
import shutil
import signal
import subprocess
import threading
import tracemalloc

import pytest
from corpus import CORPORA

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
    low = command("/tmp/a.pcap", unprivileged=True, timeout=120)
    assert low[0] == "systemd-run" and low[low.index("--") + 1 :] == cmd  # the same tshark, sandboxed
    for must in ("--wait", "--pipe", "--quiet", "--collect", "--uid=nobody", "--gid=nogroup"):
        assert must in low
    props = {low[i + 1] for i, x in enumerate(low) if x == "-p"}
    assert {
        "PrivateNetwork=yes",
        "ProtectSystem=strict",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
    } <= props
    assert {"ReadOnlyPaths=-/tmp/a.pcap", "RuntimeMaxSec=120", "RestrictAddressFamilies=AF_UNIX"} <= props


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
                "ip.dst": "192.168.77.69",
                "tcp.dstport": "80",
                "tcp.flags": "0x0002",
            }
        )
    )
    assert syn == [Syn(4.0, "10.10.10.17", 40000, "192.168.77.69", 80)]
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
    assert quic == [TlsHello(5.0, "10.10.10.17", 50000, "1.2.3.4", 443, "www.youtube.com", transport="quic")]
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


@pytest.fixture()
def scripted(monkeypatch, tmp_path):
    """tshark replaced by `sh`, started by the real subprocess.Popen with the keywords `extract` passes:
    `scripted(stdout, stderr, returncode)` has it print those and exit so, and `script=` gives it other
    shell words ($1 and $2 are the files holding stdout and stderr). Returns the list each call's argv,
    keywords and process are appended to."""
    calls = []
    popen = subprocess.Popen

    def script(stdout="", stderr="", returncode=0, script='cat "$1"; cat "$2" >&2; exit "$3"'):
        out, err = tmp_path / "stdout", tmp_path / "stderr"
        out.write_bytes(stdout.encode("utf-8", "surrogateescape"))
        err.write_bytes(stderr.encode("utf-8"))

        def run(cmd, **kw):
            proc = popen(["sh", "-c", script, "sh", str(out), str(err), str(returncode)], **kw)
            calls.append((cmd, kw, proc))
            return proc

        monkeypatch.setattr(subprocess, "Popen", run)
        return calls

    return script


@pytest.mark.parametrize(
    ("returncode", "stderr", "fails"),
    [
        (2, "appears to have been cut short in the middle of a packet", False),
        (2, 'You don\'t have permission to read the file "a.pcap".', True),
        (0, "", False),
    ],
    ids=["cut short", "no permission", "clean"],
)
def test_extract_distinguishes_cut_short_from_a_file_it_could_not_open(scripted, returncode, stderr, fails):
    """Both exit 2. A finished hourly pcap is 'cut short' (fine); a permission error must raise, or the
    pcap is marked done with zero rows (this happened in production on 2026-10-27)."""
    scripted(stderr=stderr, returncode=returncode)
    if fails:
        with pytest.raises(RuntimeError, match="tshark rc=2: You don't have permission"):
            tshark.extract("/x.pcap", unprivileged=False)
    else:
        assert tshark.extract("/x.pcap", unprivileged=False) == []


def test_extract_frames_rows_on_newline_only_and_rejects_a_shifted_row(scripted):
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
    calls = scripted(stdout, "appears to have been cut short", returncode=2)
    out = tshark.extract("/x.pcap", unprivileged=False)
    assert [type(r) for r in out] == [TlsHello, Syn, HttpRequest] and out[2].uri == "/a\x0cb"
    ((cmd, kw, _proc),) = calls
    assert cmd[0] == "tshark" and (kw["encoding"], kw["errors"]) == ("utf-8", "replace")
    assert kw["cwd"] == "/" and kw["env"]["HOME"] == "/nonexistent" and kw["env"]["LANG"] == "C.UTF-8"


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
    [
        (0, "/usr/bin/systemd-run", "systemd-run"),
        (1000, "/usr/bin/systemd-run", "tshark"),
        (1000, None, "tshark"),
    ],
)
def test_privileges_are_dropped_exactly_when_running_as_root(
    monkeypatch, scripted, euid, setpriv, first_word
):
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    monkeypatch.setattr(shutil, "which", lambda name: setpriv)
    calls = scripted()
    assert tshark.extract("/x.pcap") == []
    assert calls[0][0][0] == first_word


def test_root_without_setpriv_refuses_to_run_tshark(monkeypatch, scripted):
    """Fail closed: the dissectors parse packets from the TV and the internet, so a missing setpriv is
    one ingest warning per hour, not a silent run as root."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    calls = scripted()
    with pytest.raises(RuntimeError, match="systemd-run not found"):
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


# ---- (extractor) schema 8: the sandbox, split and nameless hellos, JA4 from fields, repeats ----------


def test_the_sandbox_carries_every_hardening_property_and_nothing_that_hides_a_failure():
    low = command("/tmp/a.pcap", unprivileged=True, timeout=120)
    props = [low[i + 1] for i, x in enumerate(low) if x == "-p"]
    assert props[: len(tshark.HARDENING)] == list(tshark.HARDENING)
    assert props[len(tshark.HARDENING) :] == ["ReadOnlyPaths=-/tmp/a.pcap", "RuntimeMaxSec=120"]
    for must in (
        "PrivateNetwork=yes",
        "ProtectSystem=strict",
        "PrivateDevices=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "RestrictNamespaces=yes",
        "ProtectProc=invisible",
        "SystemCallFilter=@system-service",
        "LimitCORE=0",
        f"MemoryMax={tshark.MEMORY_MAX}",
        f"TasksMax={tshark.TASKS_MAX}",
    ):
        assert must in props
    # a refused system call must kill tshark (ingest sees the failure), never return EPERM and let it
    # finish the file with rows missing
    assert not any(p.startswith("SystemCallErrorNumber") for p in props)
    assert len(props) == len(set(props)) and all("=" in p for p in props)


def test_reassembly_is_stated_on_the_command_line():
    cmd = command("/tmp/a.pcap")
    prefs = [cmd[i + 1] for i, x in enumerate(cmd) if x == "-o"]
    assert prefs == [
        "http.desegment_body:FALSE",
        "tcp.desegment_tcp_streams:TRUE",
        "tls.desegment_ssl_records:TRUE",
    ]


def test_only_fields_every_supported_tshark_has_are_asked_for():
    """tshark refuses to run with an unknown -e field, so a 4.2+ field (the native ja4) would break
    extraction on Debian 12's 4.0."""
    assert not any("ja4" in f or "ja3" in f or f.startswith("tls.ech") for f in FIELDS)
    assert len(FIELDS) == len(set(FIELDS))


def hello_fields(**kw):
    base = {
        "frame.time_epoch": "10",
        "ip.src": "10.10.10.17",
        "tcp.srcport": "40000",
        "ip.dst": "203.0.113.5",
        "tcp.dstport": "443",
        "tls.handshake.type": "1",
        "tls.handshake.version": "0x0303",
        "tls.handshake.extensions.supported_version": f"0x0a0a{AGG}0x0304",
        "tls.handshake.ciphersuite": f"0x1301{AGG}0x1302",
        "tls.handshake.extension.type": f"0{AGG}16{AGG}13{AGG}43",
        "tls.handshake.extensions_alpn_str": f"h2{AGG}http/1.1",
        "tls.handshake.sig_hash_alg_len": "4",
        "tls.handshake.sig_hash_alg": f"0x0403{AGG}0x0804",
        "tls.handshake.extensions_server_name": "a.example",
    }
    base.update(kw)
    return row(**base)


def test_a_hello_without_a_server_name_is_kept_with_its_fingerprint():
    (hello,) = parse_row(
        hello_fields(
            **{
                "tls.handshake.extensions_server_name": "",
                "tls.handshake.extension.type": f"16{AGG}13{AGG}43",
            }
        )
    )
    assert hello.sni == "" and hello.ja4.startswith("t13i0203h2_") and not hello.partial


def test_fingerprint_from_fields_in_decimal_or_hex():
    (a,) = parse_row(hello_fields())
    (b,) = parse_row(
        hello_fields(
            **{
                "tls.handshake.ciphersuite": f"4865{AGG}4866",
                "tls.handshake.extension.type": f"0x0000{AGG}0x0010{AGG}0x000d{AGG}0x002b",
                "tls.handshake.sig_hash_alg": f"1027{AGG}2052",
            }
        )
    )
    assert a.ja4 == b.ja4 and a.ja4.startswith("t13d0204h2_")


def test_signature_lists_that_do_not_add_up_give_no_fingerprint_rather_than_a_wrong_one():
    assert parse_row(hello_fields(**{"tls.handshake.sig_hash_alg_len": "6"}))[0].ja4 == ""
    assert parse_row(hello_fields(**{"tls.handshake.sig_hash_alg_len": f"4{AGG}4"}))[0].ja4 == ""
    assert parse_row(hello_fields(**{"tls.handshake.ciphersuite": ""}))[0].ja4 == ""
    assert parse_row(hello_fields(**{"tls.handshake.ciphersuite": "junk"}))[0].ja4 == ""


def test_signature_algorithms_are_taken_from_their_own_extension_only():
    """delegated_credentials (34) before and signature_algorithms_cert (50) after: tshark prints all
    three lists under one field."""
    exts = f"0{AGG}34{AGG}13{AGG}50{AGG}43"
    lens = f"2{AGG}4{AGG}2"
    sigs = f"0x0203{AGG}0x0403{AGG}0x0804{AGG}0x0601"
    (h,) = parse_row(
        hello_fields(
            **{
                "tls.handshake.extension.type": exts,
                "tls.handshake.sig_hash_alg_len": lens,
                "tls.handshake.sig_hash_alg": sigs,
            }
        )
    )
    i = tshark.clienthello.Ja4Input(
        "tcp", 0x0303, [0x0304], [0x1301, 0x1302], [0, 34, 13, 50, 43], b"h2", [0x0403, 0x0804]
    )
    assert h.ja4 == tshark.clienthello.ja4(i)


def test_a_quic_hello_is_fingerprinted_as_quic():
    (h,) = parse_row(
        hello_fields(**{"tcp.srcport": "", "tcp.dstport": "", "udp.srcport": "50000", "udp.dstport": "443"})
    )
    assert h.transport == "quic" and h.ja4.startswith("q13d") and (h.sport, h.dport) == (50000, 443)


def test_held_back_segment_data_that_is_not_a_hello_is_ignored():
    for data in ("", "zz", "170303000548656c6c6f", "160303000402000000", "47455420"):
        assert (
            parse_row(
                row(**{"frame.time_epoch": "1", "ip.src": "s", "ip.dst": "d", "tcp.segment_data": data})
            )
            == []
        )


def test_held_back_first_segment_of_a_hello_in_either_hex_form():
    from corpus import build

    rec = build.chrome_pq("x", "early.example.com", late_sni=False).record()[:1460]
    for data in (rec.hex(), ":".join(f"{b:02x}" for b in rec)):
        (h,) = parse_row(
            row(
                **{
                    "frame.time_epoch": "1",
                    "ip.src": "s",
                    "tcp.srcport": "4",
                    "ip.dst": "d",
                    "tcp.dstport": "443",
                    "tcp.segment_data": data,
                }
            )
        )
        assert (h.sni, h.partial, h.ja4, h.transport, h.sport) == ("early.example.com", True, "", "tcp", 4)


def H(t, sport=1, partial=False, sni="a.example", transport="tcp", dst="d"):
    return TlsHello(t, "s", sport, dst, 443, sni, partial=partial, transport=transport)


def test_dedupe_keeps_one_hello_per_attempt_and_prefers_the_whole_one():
    syn = Syn(0.5, "s", 1, "d", 443)
    rows = [
        syn,
        H(1.0, partial=True, sni=""),  # held-back first segment
        H(1.1),  # the reassembled hello: replaces it
        H(2.0),  # a retransmission: dropped
        H(1.5, sport=2),  # another connection
        H(1.6, transport="quic"),  # the same ports over QUIC: another attempt
        H(40.0),  # past REPEAT_WINDOW of the kept one: a new connection on reused ports
        H(41.0, partial=True),  # a partial after a whole one: dropped
    ]
    out = tshark.dedupe(rows)
    assert out == [syn, H(1.1), H(1.5, sport=2), H(1.6, transport="quic"), H(40.0)]


def test_extract_dedupes_what_tshark_printed(scripted):
    line = hello_fields()
    scripted("\n".join([line, line.replace("\t", "\t", 1)]) + "\n")
    assert len(tshark.extract("/x.pcap", unprivileged=False)) == 1
    assert len(tshark.extract("/x.pcap", unprivileged=False, keep_repeats=True)) == 2


# ---- (bounds) tshark read as it prints ---------------------------------------------------------------------
def printed_whole(output: bytes) -> list:
    """What `extract` returned for `output` when it took tshark's whole output from subprocess.run: decoded
    at once, its newlines translated as text mode translates them, split on newline."""
    whole = output.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    return tshark.dedupe([r for line in whole.split("\n") for r in tshark.parse_row(line)])


ROWS = sorted((CORPORA / "rows").glob("*/*.rows"))


@pytest.mark.parametrize("rows", ROWS, ids=[f"{p.parent.name}/{p.stem}" for p in ROWS])
def test_extract_gives_every_corpus_file_the_rows_it_gave_when_it_read_the_output_whole(scripted, rows):
    scripted(rows.read_text(encoding="utf-8"), "appears to have been cut short in the middle of a packet", 2)
    threads = threading.active_count()
    assert tshark.extract("/x.pcap", unprivileged=False) == printed_whole(rows.read_bytes()) != []
    assert threading.active_count() == threads  # the watchdog is gone with the call


def test_extract_holds_one_row_at_a_time_never_the_whole_output(scripted):
    """subprocess.run held all of tshark's output, and str.split a second copy: 100,000 crafted rows of an
    hour's file took the ingest's root process to 1,370 MB."""
    scripted(("x" * 2000 + "\n") * 5000)  # 10 MB of rows that are not rows
    tracemalloc.start()
    try:
        assert tshark.extract("/x.pcap", unprivileged=False) == []
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 1_000_000


def test_the_row_limit_holds_the_busiest_real_hour_eighty_times_over():
    """The reference's busiest hourly file held 5,792 packets, and a file of crafted hello-shaped segments
    printed 421 MB of rows: the limit stops the second and never the first."""
    assert tshark.ROW_LIMIT == 500_000


class Clock(BaseException):
    """What the ingest step's clock raises: no `except Exception` takes it."""


# a tshark that prints $1's row for ever, from the shell's own printf: it ends at the first write after
# its reader has gone, and leaves no process behind
FOREVER = 'row=$(cat "$1"); while :; do printf "%s\\n" "$row"; done'


@pytest.mark.parametrize(
    ("limit", "ticks", "stops"),
    [(3, 99, RuntimeError), (99, 3, Clock)],
    ids=["the row limit", "the step's clock"],
)
def test_a_tshark_that_prints_without_end_is_stopped_and_killed(monkeypatch, scripted, limit, ticks, stops):
    calls = scripted(hello_fields(), script=FOREVER)
    monkeypatch.setattr(tshark, "ROW_LIMIT", limit)
    parse, seen = tshark.parse_row, []

    def ticking(line):
        seen.append(line)
        if len(seen) == ticks:
            raise Clock
        return parse(line)

    monkeypatch.setattr(tshark, "parse_row", ticking)
    with pytest.raises(stops):
        tshark.extract("/x.pcap", unprivileged=False)
    assert len(seen) == min(limit, ticks)
    ((_cmd, _kw, proc),) = calls
    assert proc.returncode == -signal.SIGKILL  # killed, and reaped


@pytest.mark.parametrize(
    "script",
    ["exec sleep 30", f"({FOREVER}) & wait"],
    ids=["silent", "printing on in a process of its own, as a sandboxed tshark does"],
)
def test_a_tshark_past_its_timeout_is_killed_and_read_no_further_as_subprocess_run_did(scripted, script):
    """systemd-run hands its pipe to tshark in a unit of its own: killing systemd-run at the timeout leaves
    tshark printing into the pipe until the unit's own limit, and the rows must stop being read there."""
    calls = scripted(hello_fields(), script=script)
    threads = threading.active_count()
    with pytest.raises(subprocess.TimeoutExpired):
        tshark.extract("/x.pcap", timeout=0.3, unprivileged=False)
    ((_cmd, _kw, proc),) = calls
    assert proc.returncode == -signal.SIGKILL and threading.active_count() == threads


def test_summary_counts_the_tvs_hellos_by_what_could_be_read():
    rows = [
        H(1.0),
        TlsHello(2.0, "s", 2, "d", 443, "", ja4="t12i_x_y"),
        TlsHello(3.0, "s", 3, "d", 443, "q.example", True, "q13d_x_y", "quic"),
        TlsHello(4.0, "s", 4, "d", 443, "", partial=True),
        TlsHello(5.0, "other", 5, "d", 443, "x.example"),
        Syn(6.0, "s", 6, "d", 443),
    ]
    assert tshark.summary(rows, "s") == {
        "named": 2,
        "nameless": 2,
        "partial": 1,
        "quic": 1,
        "ja4": 2,
        "ech": 1,
    }
