"""The gate's kernel log lines into the store, and the brief section they feed."""

import io

from tvgw import cli, db, ingest, queries

LINE = (
    "{t} kylepi5 kernel: tvgw-gate: IN=eth0 OUT=wlan0 MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 "
    "SRC=10.10.10.17 DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=0 DF PROTO=TCP SPT=4{n:04d} DPT={dport} "
    "WINDOW=65535 RES=0x00 SYN URGP=0"
)


def lines(rows):
    return [LINE.format(t=t, dst=dst, dport=dport, n=i) for i, (t, dst, dport) in enumerate(rows)]


def test_gate_lines_land_once_and_the_brief_names_what_a_hello_explains(tmp_path, lg):
    conn = db.connect(str(tmp_path / "g.db"))
    base = 1793020000
    rows = [
        (base + 10, "96.6.235.59", 443),
        (base + 20, "96.6.235.59", 443),
        (base + 30, "203.0.113.9", 8080),
    ]
    assert ingest.ingest_gate(conn, lambda since: lines(rows)) == 3
    assert ingest.ingest_gate(conn, lambda since: lines(rows)) == 0  # the same lines again: nothing new
    assert conn.execute("SELECT COUNT(*), MAX(dport) FROM gate").fetchone() == (3, 8080)
    conn.execute(
        "INSERT INTO tls(t,dst,dport,sport,sni) VALUES (?, '203.0.113.9', 443, 40001, 'known.example')",
        (base + 5,),
    )
    for t, packets in ((base - 600, 0), (base + 600, 7)):
        conn.execute(
            "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, 'TV to an address DNS never returned', ?, 0)",
            (t, packets),
        )
    conn.commit()
    ex = queries.gate_examples(conn, base - 1000, base + 1000)
    assert [(e["dst"], e["dport"], e["n"], e["name"]) for e in ex] == [
        ("96.6.235.59", 443, 2, None),
        ("203.0.113.9", 8080, 1, "known.example"),
    ]
    o = queries.window_report(conn, base - 1000, base + 1000, lg, now=base + 1000)
    assert o["gate"]["new_connections"] == 7 and len(o["gate"]["examples"]) == 2
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert "DNS-gated egress (count-only): 7 new connections" in text
    assert "96.6.235.59" in text and "known.example" in text and "(none)" in text
    assert o["coverage"]["sources"]["gate"]["rows"] == 3


def test_the_gate_count_is_never_below_the_samples_it_logged(tmp_path, lg):
    """Reproduced on the gateway: every apply flushes the gate's chain and zeroes its counter, and the
    brief said 3 new connections above 10 logged samples. The rule counts before it samples
    (`counter limit rate 6/minute log`), so each sample is a counted connection."""
    conn = db.connect(str(tmp_path / "g.db"))
    base = 1793020000
    ingest.ingest_gate(conn, lambda since: lines([(base + 10 * i, f"203.0.113.{i}", 443) for i in range(5)]))
    for t, packets in ((base - 600, 0), (base + 300, 2), (base + 900, 1)):  # a re-apply between the two
        conn.execute(
            "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, 'TV to an address DNS never returned', ?, 0)",
            (t, packets),
        )
    conn.commit()
    o = queries.window_report(conn, base - 1000, base + 1000, lg, now=base + 1000)
    assert o["gate"]["new_connections"] == 5
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert "to addresses DNS never gave 5;" in text  # Firewall held agrees with the section
    assert "DNS-gated egress (count-only): 5 new connections" in text
