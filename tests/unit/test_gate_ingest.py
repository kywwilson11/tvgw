"""The gate's kernel log lines into the store, and the brief section they feed."""

import io

from conftest import plan, statements

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


def test_a_sample_moments_after_an_answer_naming_its_address_is_the_feeder_late(tmp_path, lg):
    """Reproduced on the live store: six of six samples came 1 to 5 ms after a cached answer for the
    same address. The feeder adds an address once the answer has left the Pi, and the TV connects
    within milliseconds, so its first connection can beat the add. That is not a forgotten lookup and
    not a bypass, and the brief must not read it as either."""
    conn = db.connect(str(tmp_path / "g.db"))
    base = 1793020000
    rows = [
        (base + 10, "96.6.235.59", 443),  # 3 ms after an answer naming it: the feeder was late
        (base + 70, "96.6.235.59", 443),  # a minute later: the answer is no excuse any more
        (base + 30, "203.0.113.9", 443),  # an hour after its answer: a lookup the gate forgot
    ]
    ingest.ingest_gate(conn, lambda since: lines(rows))
    conn.executemany(
        "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, ?, 'A', ?, 0)",
        [
            (base + 9.997, "cdn.example", "CNAME:edge.example,A:96.6.235.5,A:96.6.235.59"),
            (base + 29.999, "other.example", "A:96.6.235.590"),  # not the address, though it begins with it
            (base - 3600, "known.example", "A:203.0.113.9"),
        ],
    )
    conn.commit()
    ran = statements(conn, lambda: queries.gate_examples(conn, base - 1000, base + 1000))
    assert not [sql for sql in ran if "SCAN d" in plan(conn, sql)]  # never a pass over the whole dns table
    ex = {e["dst"]: e for e in queries.gate_examples(conn, base - 1000, base + 1000)}
    assert (ex["96.6.235.59"]["n"], ex["96.6.235.59"]["late"]) == (2, 1)
    assert ex["203.0.113.9"]["late"] == 0
    o = queries.window_report(conn, base - 1000, base + 1000, lg, now=base + 1000)
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert "just looked up" in text and "a lookup the gate had forgotten" not in text


def test_the_gate_headline_is_never_below_the_samples_it_lists(tmp_path, lg):
    """Reproduced on the live store: the counter's steps read 2, 3, 2, 0, 0 (3 new connections) over a
    window holding 11 samples, each counted before it was logged; the resets in between took the rest."""
    conn = db.connect(str(tmp_path / "g.db"))
    base = 1793020000
    ingest.ingest_gate(conn, lambda since: lines([(base + 60 * i, "203.0.113.9", 443) for i in range(11)]))
    for i, packets in enumerate((2, 3, 2, 0, 0)):
        conn.execute(
            "INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?, ?, ?, 0)",
            (base + 600 * i, queries.GATE_RULE, packets),
        )
    conn.commit()
    o = queries.window_report(conn, base - 1, base + 3600, lg, now=base + 3600)
    assert o["gate"]["new_connections"] == 11
