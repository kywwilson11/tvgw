"""Queries, the daily brief and the CLI, on a store built from the fake gateway."""

import io
import json

import pytest
from conftest import fake_extract, fake_oddport

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


def test_brief_contents(store):
    conn = db.connect(store.db_path, readonly=True)
    o = queries.brief(conn, "2026-10-26")
    assert o["dns"] == {"lookups": 2, "blocked": 1, "names": 2}
    assert o["flows"]["conns"] == 2 and o["flows"]["bytes_up"] == 2259 + 64
    names = {h["name"]: h for h in o["new_hosts"]}
    assert names["aic.recommend.lgtvcommon.com"]["blocked"] == 1
    assert o["blocked_retries"] == [
        {"name": "aic.recommend.lgtvcommon.com", "lookups": 1, "rule": "||recommend.lgtvcommon.com^"}
    ]
    assert o["allowed_non_streaming"] == [{"name": "us.lgtvsdp.com", "lookups": 1}]
    assert o["top_upload"][0]["dst"] == "142.251.219.1" and o["top_upload"][0]["bytes_up"] == 2259
    assert {(g["status"], g["biz_code"]) for g in o["gfts"]} == {(403, "PREMIUM"), (200, "APP_STORE")}
    assert o["oddports"] == [{"proto": "TCP", "dst": "156.147.69.32", "dport": 8080, "n": 1}]
    assert [s["power"] for s in o["tvstate"]] == ["unreachable", "Active"]
    assert len(o["rule_changes"]) == 5


def test_brief_for_an_empty_day(store):
    conn = db.connect(store.db_path, readonly=True)
    o = queries.brief(conn, "2020-01-01")
    assert (
        o["dns"] == {"lookups": 0, "blocked": 0, "names": 0}
        and o["new_hosts"] == []
        and o["top_upload"] == []
    )
    buf = io.StringIO()
    cli.render_brief(o, buf)
    assert "(none)" in buf.getvalue() and "Unexpected ports: none" in buf.getvalue()


def test_render_brief_text(store):
    conn = db.connect(store.db_path, readonly=True)
    buf = io.StringIO()
    cli.render_brief(queries.brief(conn, "2026-10-26"), buf)
    text = buf.getvalue()
    assert "2 lookups (1 blocked, 2 names)" in text
    assert "aic.recommend.lgtvcommon.com" in text and "BLOCKED" in text
    assert "403 PREMIUM: 1" in text and "TCP/8080 -> 156.147.69.32 x1" in text
    assert "09:19=Active" in text


def test_host_detail_and_gfts_and_tvstate(store):
    conn = db.connect(store.db_path, readonly=True)
    h = queries.host_detail(conn, "GFTS.lge.com")
    assert h["category"] == "LG core" and h["ips"] == [("23.5.6.43", 1)] and h["tls_n"] == 1
    assert queries.host_detail(conn, "never.seen") is None
    g = queries.gfts_summary(conn, 0)
    assert (403, "PREMIUM", 1, 153) in g and (200, "APP_STORE", 1, 6488) in g
    assert [p for _, p, _ in queries.tvstate(conn, 0)] == ["unreachable", "Active"]
    assert [k for _, k, _ in queries.settings_changes(conn, 0)] == ["option.livePlus", "option.zipcode"]
    assert len(queries.rules_history(conn)) == 5
    assert queries.allowed_non_streaming(conn, 0)[0][0] == "us.lgtvsdp.com"
    assert queries.new_hosts(conn, 0)[0][0]  # ordered by first seen, non-empty


def test_hb_and_table_and_state_word():
    assert cli.hb(0) == "0B" and cli.hb(1023) == "1023B" and cli.hb(2048) == "2.0K"
    assert cli.hb(5 * 1024**3) == "5.0G" and cli.hb(None) == "0B"
    buf = io.StringIO()
    cli.table([("a", 1), ("bbb", 22)], ["name", "n"], buf)
    assert buf.getvalue().splitlines() == ["name  n ", "a     1 ", "bbb   22"]
    assert (cli.state_word(1), cli.state_word(0), cli.state_word(None)) == ("BLOCKED", "allowed", "?")


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
