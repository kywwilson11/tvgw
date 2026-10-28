"""Queries, the daily brief and the CLI, on a store built from the fake gateway."""

import io
import json

import pytest
from conftest import NOW, fake_extract, fake_oddport

from tvgw import cli, db, ingest, queries


@pytest.fixture()
def store(gateway, lg):
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    return gateway


def test_since_epoch_and_day_bounds():
    now = 1_000_000.0
    assert queries.since_epoch("2h", now) == now - 7200
    assert queries.since_epoch("1d", now) == now - 86400
    assert queries.since_epoch("1.5w", now) == now - 1.5 * 604800
    a, b = queries.day_bounds("2026-10-26")
    assert b - a == 86400
    with pytest.raises(ValueError):
        queries.since_epoch("soon")


def test_brief_contents(store, lg):
    conn = db.connect(store.db_path, readonly=True)
    o = queries.brief(conn, "2026-10-26", lg, now=NOW + 3600)
    assert o["dns"] == {"lookups": 2, "blocked": 1, "names": 2}
    assert o["flows"]["conns"] == 2 and o["flows"]["bytes_up"] == 2259 + 64
    names = {h["name"]: h for h in o["new_hosts"]}
    assert names["aic.recommend.lgtvcommon.com"]["blocked"] == 1
    # gfts.lge.com (TLS, 09:08:20) is the first lge.com name; ngfts.lge.com two seconds later is not a new domain
    assert names["gfts.lge.com"]["new_domain"] is True and names["ngfts.lge.com"]["new_domain"] is False
    assert names["us.lgtvsdp.com"]["new_domain"] is True
    assert "239.255.255.250:1900" not in names
    assert o["blocked_retries"] == [
        {"name": "aic.recommend.lgtvcommon.com", "lookups": 1, "rule": "||recommend.lgtvcommon.com^"}
    ]
    # us.lgtvsdp.com is LG core: expected for an LG profile, so nothing is "allowed, unexpected"
    assert o["allowed_unexpected"] == []
    top = o["top_upload"][0]
    assert (
        top["dst"] == "142.251.219.1" and top["bytes_up"] == 2259 and top["name"] is None and top["ips"] == 1
    )
    assert {(g["status"], g["biz_code"]) for g in o["gfts"]} == {(403, "PREMIUM"), (200, "APP_STORE")}
    assert o["oddports"] == [{"proto": "TCP", "dst": "156.147.69.32", "dport": 8080, "n": 1}]
    assert o["lan_probes"] == [{"dst": "192.168.8.69", "proto": "tcp", "dport": 80, "n": 1}]
    assert o["dns_anomalies"] == []
    assert [s["power"] for s in o["tvstate"]] == ["unreachable", "Active"]
    assert len(o["rule_changes"]) == 5
    cov = o["coverage"]
    assert cov["warnings"] == [] and cov["sources"]["dns"]["rows"] == 2
    assert cov["not_assessed"] == ["verify"]  # every source was read at the (fake) last run; verify never ran


def test_coverage_calls_a_stale_source_not_assessed(store, lg):
    conn = db.connect(store.db_path, readonly=True)
    read_at = float(db.get_meta(conn, "last_run"))
    cov = queries.coverage(conn, read_at - 86400, read_at + 86400 * 3, now=read_at + 86400 * 3)
    assert set(cov["not_assessed"]) == set(cov["sources"])  # everything read long before the window closed
    live = queries.coverage(conn, read_at - 3600, read_at + 3600, now=read_at + 60)
    assert live["not_assessed"] == ["verify"]


def test_blocked_retries_and_allowed_respect_the_day_end(store, lg):
    conn = db.connect(store.db_path)
    conn.execute(
        "INSERT INTO dns(t,qname,blocked,rule) VALUES (1793120000, 'aic.recommend.lgtvcommon.com', 1, 'r')"
    )
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (1793120001, 'telemetry.example.net', 0)")
    conn.commit()
    a, b = queries.day_bounds("2026-10-26")
    assert queries.blocked_retries(conn, a, b)[0][1] == 1  # the lookup on the next day is not counted
    assert queries.blocked_retries(conn, a)[0][1] == 2
    assert queries.allowed_unexpected(conn, a, b, lg) == []
    assert [r[:3] for r in queries.allowed_unexpected(conn, a, None, lg)] == [
        ("telemetry.example.net", "Other", 1)
    ]
    conn.close()


def test_flows_are_named_by_their_own_tls_hello_not_by_a_shared_ip(store, lg):
    conn = db.connect(store.db_path)
    # two connections to one CDN address: a tracker's hello on port 40001 and a video hello on 40009
    conn.execute(
        "INSERT INTO tls(t,dst,dport,sport,sni) VALUES (1793020100, '23.5.6.43', 443, 40001, 'gfts.lge.com')"
    )
    conn.execute(
        "INSERT INTO tls(t,dst,dport,sport,sni) VALUES (1793020300, '23.5.6.43', 443, 40009, 'video.example.net')"
    )
    conn.execute(
        "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,bytes_up,bytes_down) "
        "VALUES (1793020110, 1793020200, 'tcp', '23.5.6.43', 443, 40001, 1000, 5000)"
    )  # conntrack's start is 10 s after the hello: within FLOW_SLACK
    conn.execute(
        "INSERT INTO flows(t_start,t_end,proto,dst,dport,sport,bytes_up,bytes_down) "
        "VALUES (1793020299, 1793020900, 'tcp', '23.5.6.43', 443, 40009, 7000, 900000)"
    )
    conn.commit()
    a, b = queries.day_bounds("2026-10-26")
    rows = {r[0]: r for r in queries.top_upload(conn, a, b)}
    assert rows["video.example.net"][4:7] == (1, 7000, 900000)
    assert rows["gfts.lge.com"][4:7] == (1, 1000, 5000)
    h = queries.host_detail(conn, "gfts.lge.com")
    assert (h["conns"], h["bytes_up"], h["bytes_down"]) == (1, 1000, 5000)
    conn.close()


def test_dns_anomalies_flag_data_shaped_names_outside_expected_categories(store, lg):
    conn = db.connect(store.db_path)
    long = "a" * 60 + "." + "b" * 60 + ".tracker.example"
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (1793020000, ?, 0)", (long,))
    conn.execute("INSERT INTO dns(t,qname,blocked) VALUES (1793020000, 'x7k2p9q4m1z8w3v6.beacon.example', 1)")
    conn.execute(
        "INSERT INTO dns(t,qname,blocked) VALUES (1793020000, 'rr4---sn-bvvbaxivnuxqjvhj5nu-n4v6.googlevideo.com', 0)"
    )
    conn.executemany(
        "INSERT INTO dns(t,qname,blocked) VALUES (1793020000, ?, 0)",
        [(f"s{i}.fan.example",) for i in range(201)],
    )
    conn.commit()
    a, b = queries.day_bounds("2026-10-26")
    found = {(x["kind"], x["name"]) for x in queries.dns_anomalies(conn, a, b, lg)}
    assert ("long name", long) in found
    assert ("random label", "x7k2p9q4m1z8w3v6.beacon.example") in found
    assert ("fan-out", "fan.example") in found
    assert not any("googlevideo" in n for _, n in found)  # Streaming is expected, however odd the label
    conn.close()


def test_fan_out_is_judged_per_day_and_reports_real_lookups(store, lg):
    """FANOUT is documented per day; applied to a week it tripped at a seventh of the rate, and the row
    put a name count in the lookups column."""
    conn = db.connect(store.db_path)
    a, b = queries.day_bounds("2026-10-26")
    week_a, week_b = a - 3 * 86400, a + 4 * 86400
    conn.executemany(
        "INSERT INTO dns(t,qname,blocked) VALUES (?, ?, 0)",
        [(week_a + i * (7 * 86400 // 201), f"s{i}.fan.example") for i in range(201)],
    )
    conn.commit()
    assert not any(x["kind"] == "fan-out" for x in queries.dns_anomalies(conn, week_a, week_b, lg))
    conn.execute("UPDATE dns SET t=? WHERE qname LIKE '%.fan.example'", (a + 3600,))
    conn.executemany(
        "INSERT INTO dns(t,qname,blocked) VALUES (?, 's0.fan.example', 0)", [(a + 3700,), (a + 3800,)]
    )
    conn.commit()
    (row,) = [x for x in queries.dns_anomalies(conn, a, b, lg) if x["kind"] == "fan-out"]
    assert row["name"] == "fan.example" and row["lookups"] == 203
    assert row["detail"] == "201 distinct names over 1 day(s)"
    conn.close()


def test_all_hex_identifiers_are_random_labels_even_at_low_entropy(store, lg):
    """Monte Carlo: the 3.6-bit threshold flags 3% of 16-character hex ids; an exact hex rule catches
    the commonest generated-label class with no false positive on English labels."""
    conn = db.connect(store.db_path)
    conn.executemany(
        "INSERT INTO dns(t,qname,blocked) VALUES (1793020000, ?, 0)",
        [("3f9a0c1d2e4b5a67.beacon.example",), ("deadbeefcafebabe.beacon.example",)],
    )
    conn.commit()
    a, b = queries.day_bounds("2026-10-26")
    found = {x["name"]: x for x in queries.dns_anomalies(conn, a, b, lg)}
    assert found["3f9a0c1d2e4b5a67.beacon.example"]["kind"] == "random label"
    assert found["3f9a0c1d2e4b5a67.beacon.example"]["detail"] == "all-hex 16 chars"
    assert "deadbeefcafebabe.beacon.example" not in found  # letters only: a word, for all the rule knows
    conn.close()


def test_brief_for_an_empty_day(store, lg):
    conn = db.connect(store.db_path, readonly=True)
    o = queries.brief(conn, "2020-01-01", lg)
    assert (
        o["dns"] == {"lookups": 0, "blocked": 0, "names": 0}
        and o["new_hosts"] == []
        and o["top_upload"] == []
    )
    buf = io.StringIO()
    cli.render_brief(o, buf)
    assert "(none)" in buf.getvalue() and "Unexpected ports: none" in buf.getvalue()


def test_render_brief_text(store, lg):
    conn = db.connect(store.db_path, readonly=True)
    buf = io.StringIO()
    cli.render_brief(queries.brief(conn, "2026-10-26", lg, now=NOW + 3600), buf)
    text = buf.getvalue()
    assert "2 lookups (1 blocked, 2 names)" in text
    assert "aic.recommend.lgtvcommon.com" in text and "BLOCKED" in text
    assert "403 PREMIUM: 1" in text and "TCP/8080 -> 156.147.69.32 x1" in text
    assert "LAN probes (dropped): 192.168.8.69:80 x1" in text
    assert "Coverage: flows 2, dns 2" in text and "NOT ASSESSED (source not read recently): verify" in text
    assert "09:19=Active" in text


def test_host_detail_and_gfts_and_tvstate(store, lg):
    conn = db.connect(store.db_path, readonly=True)
    h = queries.host_detail(conn, "GFTS.lge.com")
    assert h["category"] == "LG core" and h["ips"] == [("23.5.6.43", 1)] and h["tls_n"] == 1
    assert queries.host_detail(conn, "never.seen") is None
    g = queries.gfts_summary(conn, 0)
    assert (403, "PREMIUM", 1, 153) in g and (200, "APP_STORE", 1, 6488) in g
    assert [p for _, p, _ in queries.tvstate(conn, 0)] == ["unreachable", "Active"]
    assert [k for _, k, _ in queries.settings_changes(conn, 0)] == ["option.livePlus", "option.zipcode"]
    assert len(queries.rules_history(conn)) == 5
    assert queries.allowed_unexpected(conn, 0, None, lg) == []
    assert queries.new_hosts(conn, 0)[0][0]  # ordered by first seen, non-empty


def test_hb_and_table_and_state_word():
    assert cli.hb(0) == "0B" and cli.hb(1023) == "1023B" and cli.hb(2048) == "2.0K"
    assert cli.hb(5 * 1024**3) == "5.0G" and cli.hb(None) == "0B"
    buf = io.StringIO()
    cli.table([("a", 1), ("bbb", 22)], ["name", "n"], buf)
    assert buf.getvalue().splitlines() == ["name  n ", "a     1 ", "bbb   22"]
    buf = io.StringIO()
    cli.table([("evil\x1b[2Jname\n", 1)], ["name", "n"], buf)  # TV-supplied text cannot drive the terminal
    assert "\x1b" not in buf.getvalue() and "\\x1b[2Jname\\x0a" in buf.getvalue()
    assert (cli.state_word(1), cli.state_word(0), cli.state_word(None)) == ("BLOCKED", "allowed", "?")


def test_clean_escapes_every_non_printable_code_point_and_keeps_the_rest():
    """A bidi override or a zero-width space in a user agent or device name can reorder a table row on
    the terminal and in the archived reports; the old table escaped C0, DEL and C1 only."""
    assert cli.clean("a\u202eb\u200bc") == "a\\u202eb\\u200bc"
    assert cli.clean("x\U0001f600") == "x\U0001f600"  # printable, so untouched
    assert cli.clean("\x1b[2J\n\x07\x9b") == "\\x1b[2J\\x0a\\x07\\x9b"
    assert cli.clean("plain text, ünïcödé and 日本") == "plain text, ünïcödé and 日本"
    assert cli.clean("\U000e0001") == "\\U000e0001"  # a tag character, outside the BMP


def test_render_cleans_the_label_power_and_firmware_strings(store, lg):
    conn = db.connect(store.db_path, readonly=True)
    o = queries.brief(conn, "2026-10-26", lg, now=NOW + 3600)
    o["label"] = "2026-10-26\x1b[2J"
    o["tvstate"][1]["power"] = "Act\x1bive"
    o["firmware_changes"] = [{"t": NOW, "firmware": "04.65\u202e.10", "new_hosts": []}]
    buf = io.StringIO()
    cli.render_brief(o, buf)
    text = buf.getvalue()
    assert "\x1b" not in text and "\u202e" not in text
    assert (
        "=== 2026-10-26\\x1b[2J:" in text
        and "09:19=Act\\x1bive" in text
        and "Firmware 04.65\\u202e.10" in text
    )


def test_cli_end_to_end(store, tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'TV_IP={store.tv_ip}\nDB_PATH="{store.db_path}"\nDB_DAYS=30\n')
    assert cli.main(["--conf", str(conf), "size"]) == 0
    out = capsys.readouterr().out
    assert "dns" in out and "file:" in out
    assert cli.main(["--conf", str(conf), "brief", "2026-10-26", "--json"]) == 0
    o = json.loads(capsys.readouterr().out)
    assert o["day"] == "2026-10-26" and o["dns"]["lookups"] == 2
    assert cli.main(["--conf", str(conf), "host", "us.lgtvsdp.com"]) == 0
    assert "LG core" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf), "host", "nobody.example"]) == 1
    capsys.readouterr()
    assert cli.main(["--conf", str(conf), "sql", "select count(*) as n from dns"]) == 0
    assert "2" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.main(["--conf", str(conf), "sql", "delete from dns"])
    with pytest.raises(SystemExit, match="sql:"):
        cli.main(["--conf", str(conf), "sql", "select * from no_such_table"])
    for sub in ("new-hosts", "retries", "allowed", "top-upload", "gfts", "tvstate", "rules"):
        assert cli.main(["--conf", str(conf), sub]) == 0, sub
        capsys.readouterr()
    with pytest.raises(SystemExit):
        cli.main(["--conf", str(conf), "--db", str(tmp_path / "missing.db"), "size"])


def test_cli_missing_db_exits_cleanly(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"DB_PATH={tmp_path}/none.db\n")
    with pytest.raises(SystemExit) as e:
        cli.main(["--conf", str(conf), "size"])
    assert "tvgw ingest" in str(e.value)


def test_cli_rejects_a_bad_conf_value_with_a_message(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("DB_DAYS=0\n")
    with pytest.raises(SystemExit, match="DB_DAYS"):
        cli.main(["--conf", str(conf), "size"])
    conf.write_text("DB_DAYS=soon\n")
    with pytest.raises(SystemExit, match="whole number"):
        cli.main(["--conf", str(conf), "size"])


def test_ingest_exit_status_reflects_warnings(store, tmp_path, capsys, monkeypatch):
    from tvgw import ingest as ingest_mod

    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'TV_IP={store.tv_ip}\nDB_PATH="{store.db_path}"\n')
    monkeypatch.setattr(ingest_mod, "run", lambda s, p: ingest_mod.Stats(warnings=["dns: boom"]))
    assert cli.main(["--conf", str(conf), "ingest"]) == 1
    assert "WARNING dns: boom" in capsys.readouterr().err
    monkeypatch.setattr(ingest_mod, "run", lambda s, p: ingest_mod.Stats())
    assert cli.main(["--conf", str(conf), "ingest"]) == 0


def test_cli_profile_command(store, tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'TV_IP={store.tv_ip}\nDB_PATH="{store.db_path}"\n')
    assert cli.main(["--conf", str(conf), "profile"]) == 0
    out = capsys.readouterr().out
    assert (
        "rules lint: clean" in out
        and "us.lgtvsdp.com" in out
        and "webOS 5 (2020, jhericurl; verified here)" in out
    )
    assert cli.main(["--conf", str(conf), "profile", "--model", "OLED65C2PUA", "--webos", "22"]) == 0
    out = capsys.readouterr().out
    assert (
        "YES, built-in far-field microphone" in out and "audio checklist:" in out and "webOS 22 (2022" in out
    )
    assert "webOS 5 (" not in out  # only the asked-for generation
    assert cli.main(["--conf", str(conf), "profile", "--model", "OLED55CXPUA"]) == 0
    assert "no built-in microphone" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf), "profile", "--model", "SONY-XR65", "--firmware", "99.1"]) == 0
    out = capsys.readouterr().out
    assert "model unknown" in out and "unknown to this profile" in out


def test_cli_profile_uses_the_model_the_tv_reported(store, tmp_path, capsys):
    conn = db.connect(store.db_path)
    conn.execute("INSERT INTO tvsettings(t,key,value) VALUES (1793024000, 'model', 'OLED55CXPUA')")
    conn.commit()
    conn.close()
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f'TV_IP={store.tv_ip}\nDB_PATH="{store.db_path}"\n')
    assert cli.main(["--conf", str(conf), "profile"]) == 0
    out = capsys.readouterr().out
    assert "Hardware for OLED55CXPUA (the model the TV reported over its LAN API)" in out
    assert "no built-in microphone" in out
