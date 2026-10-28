"""The DNS gate's feeder: pcap stream, Ethernet/IPv4/UDP, DNS answers, nft batches, the loop."""

import io
import struct

import pytest

from tvgw import config, dnsgate

MAGIC_LE = b"\xd4\xc3\xb2\xa1"


def dns_response(qname="cdn.example", answers=(), rcode=0):
    """A minimal DNS response: one question, the given (type, ttl, rdata bytes) answers."""
    labels = b"".join(bytes([len(x)]) + x.encode() for x in qname.split(".")) + b"\x00"
    msg = (
        struct.pack(">HHHHHH", 0x1234, 0x8180 | rcode, 1, len(answers), 0, 0)
        + labels
        + struct.pack(">HH", 1, 1)
    )
    for rtype, ttl, rdata in answers:
        msg += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return msg


def a_rdata(ip):
    return bytes(int(x) for x in ip.split("."))


def frame(payload, src="10.10.10.1", dst="10.10.10.17", sport=53, dport=40000, vlan=False, proto=17, frag=0):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = (
        struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, frag, 64, proto, 0, a_rdata(src), a_rdata(dst)
        )
        + udp
    )
    eth = b"\x00" * 12 + (b"\x81\x00\x00\x05\x08\x00" if vlan else b"\x08\x00")
    return eth + ip


def pcap(frames, magic=MAGIC_LE, linktype=1):
    order = "<" if magic in (MAGIC_LE, b"\x4d\x3c\xb2\xa1") else ">"
    out = magic + struct.pack(order + "HHiIII", 2, 4, 0, 0, 262144, linktype)
    for i, f in enumerate(frames):
        out += struct.pack(order + "IIII", 1793020000 + i, 0, len(f), len(f)) + f
    return out


def test_addresses_keeps_reachable_a_records_once_each():
    msg = dns_response(
        answers=[
            (5, 300, b"\x03cdn\x07example\x00"),  # CNAME: not an address
            (1, 300, a_rdata("203.0.113.5")),
            (1, 300, a_rdata("203.0.113.5")),  # repeated
            (1, 60, a_rdata("0.0.0.0")),  # a blocked answer
            (1, 60, a_rdata("127.0.0.1")),
            (1, 60, a_rdata("224.0.0.9")),
            (28, 60, b"\x20\x01" + b"\x00" * 14),  # AAAA
            (1, 3600, a_rdata("198.51.100.7")),
        ]
    )
    assert dnsgate.addresses(msg) == ["203.0.113.5", "198.51.100.7"]
    assert dnsgate.addresses(b"\x00\x01") == [] and dnsgate.addresses(b"garbage" * 5) == []


def test_udp_payload_handles_plain_and_vlan_frames_and_rejects_the_rest():
    msg = dns_response(answers=[(1, 60, a_rdata("203.0.113.5"))])
    assert dnsgate.udp_payload(frame(msg)) == msg
    assert dnsgate.udp_payload(frame(msg, vlan=True)) == msg
    assert dnsgate.udp_payload(frame(msg, proto=6)) is None  # TCP
    assert dnsgate.udp_payload(frame(msg, frag=0x0001)) is None  # a later fragment
    assert dnsgate.udp_payload(b"\x00" * 10) is None
    assert dnsgate.udp_payload(b"\x00" * 12 + b"\x86\xdd" + b"\x00" * 40) is None  # IPv6


def test_pcap_records_check_the_magic_and_link_type():
    msgs = [dns_response(answers=[(1, 60, a_rdata(f"203.0.113.{i}"))]) for i in range(3)]
    stream = io.BytesIO(pcap([frame(m) for m in msgs]))
    got = list(dnsgate.pcap_records(stream.read))
    assert [dnsgate.udp_payload(f) for f in got] == msgs
    with pytest.raises(RuntimeError, match="not a pcap"):
        list(dnsgate.pcap_records(io.BytesIO(b"\x00" * 40).read))
    with pytest.raises(RuntimeError, match="link type"):
        list(dnsgate.pcap_records(io.BytesIO(pcap([], linktype=113)).read))
    big_endian = pcap([frame(msgs[0])], magic=b"\xa1\xb2\xc3\xd4")
    assert [dnsgate.udp_payload(f) for f in dnsgate.pcap_records(io.BytesIO(big_endian).read)] == [msgs[0]]
    with pytest.raises(dnsgate.StreamEnded):  # a stream cut mid-record
        list(dnsgate.pcap_records(io.BytesIO(pcap([frame(msgs[0])])[:-5]).read))


def test_feed_batches_each_answer_and_rate_limits_nft_complaints():
    msgs = [
        dns_response(answers=[(1, 60, a_rdata("203.0.113.5")), (1, 60, a_rdata("203.0.113.6"))]),
        dns_response(answers=[(1, 60, a_rdata("0.0.0.0"))]),  # blocked: nothing to add
        dns_response(answers=[(1, 60, a_rdata("198.51.100.7"))]),
    ]
    scripts, logs, rcs = [], [], iter([0, 1, 1])
    clock = iter([100.0, 100.5]).__next__  # one call per refused batch; the second is inside the minute
    added = dnsgate.feed(
        io.BytesIO(pcap([frame(m) for m in msgs] + [frame(msgs[2])])).read,
        lambda script: (scripts.append(script), next(rcs))[1],
        logs.append,
        clock,
    )
    assert added == 2
    assert (
        scripts[0]
        == "add element inet tvgw_gate resolved4 { 203.0.113.5 timeout 86400s, 203.0.113.6 timeout 86400s }\n"
    )
    assert len(scripts) == 3 and all(s.endswith("}\n") for s in scripts)
    assert len(logs) == 1 and "nft refused 1 address" in logs[0]  # the second failure is inside the minute


def test_tcpdump_argv_and_off_switch():
    s = config.Settings(tv_ip="10.10.10.17", gw_ip="10.10.10.1", tv_if="eth0")
    argv = dnsgate.tcpdump_argv(s)
    assert argv[:2] == ["tcpdump", "-i"] and "-w" in argv and argv[argv.index("-w") + 1] == "-"
    assert (
        argv[argv.index("-Z") + 1] == "root"
    )  # the unit is the sandbox; a privilege drop needs a cap it lacks
    assert (
        " ".join(argv[argv.index("-") + 1 :])
        == "udp and src host 10.10.10.1 and src port 53 and dst host 10.10.10.17"
    )
    assert dnsgate.main(config.Settings(dnsgate="off")) == 0
    assert config.CHOICES["DNSGATE"] == ("off", "count") and config.Settings().dnsgate == "count"


def test_the_feeder_gets_each_answer_as_it_leaves():
    """Reproduced on the live store: every sample after a feeder start came 1 to 5 ms after a cached
    answer for its address. Without immediate mode libpcap holds a lone answer in its ring for up to
    its one-second timeout (-U flushes only tcpdump's own writes), so the add always lost the race."""
    argv = dnsgate.tcpdump_argv(config.Settings())
    assert "--immediate-mode" in argv[: argv.index("-w")]


def test_a_near_miss_switch_value_is_refused(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("DNSGATE=yes\n")
    with pytest.raises(ValueError, match="DNSGATE"):
        config.load(str(conf))
