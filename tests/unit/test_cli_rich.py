"""CLI rendering of the branches the fake gateway never reaches: HTTP/TLS detail, removed rules, empty sections."""

import json
from datetime import datetime, timedelta

import pytest

from tvgw import cli, db, queries
from tvgw.adguard import parse_time

D0 = parse_time("2026-10-25T12:00:00-05:00")
D1 = parse_time("2026-10-26T12:00:00-05:00")


@pytest.fixture()
def rich(tmp_path):
    path = tmp_path / "rich.db"
    c = db.connect(str(path))
    c.execute(
        "INSERT INTO hosts(name, first_seen, last_seen, category, dns_n, tls_n, http_n, last_blocked, last_rule) "
        "VALUES ('h.example', ?, ?, 'Cat', 3, 2, 5, 1, 'r2')",
        (D0, D1),
    )
    c.executemany(
        "INSERT INTO dns(t, qname, blocked, rule) VALUES (?,?,?,?)",
        [
            (D0, "h.example", 0, "r1"),
            (D1, "h.example", 1, "r1"),
            (D1 + 1, "h.example", 1, "r2"),
            (D0, "ads.example", 1, "||ads^"),
            (D1, "ads.example", 1, "||ads^"),
        ],
    )
    c.executemany(
        "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (1,?,443,1,'h.example')",
        [("9.9.9.9",), ("9.9.9.9",), ("8.8.8.8",)],
    )
    c.executemany(
        "INSERT INTO flows(t_end, dst, bytes_up, bytes_down) VALUES (1,?,?,?)",
        [("9.9.9.9", 10, 100), ("9.9.9.9", 20, 200), ("8.8.8.8", 1, 2)],
    )
    c.executemany("INSERT INTO http(t, host, status, src) VALUES (1,'h.example',?,'gfts')", [(200,), (403,)])
    c.executemany(
        "INSERT INTO rules(kind, text, first_seen, last_seen, removed_at) VALUES (?,?,?,?,?)",
        [("adguard", "||old^", D0, D0, D1), ("adguard", "||live^", D0, D1, None)],
    )
    c.executemany("INSERT INTO tvstate(t, power, app) VALUES (?,?,?)", [(D1, None, None)])
    c.executemany(
        "INSERT INTO oddport(t, proto, dst, dport) VALUES (?,?,?,?)",
        [(D1, "TCP", "1.1.1.1", 80), (D1, "UDP", "2.2.2.2", 9)],
    )
    c.commit()
    c.close()
    return ["--db", str(path), "--conf", str(tmp_path / "none.conf")]


def run(capsys, rich, *argv):
    assert cli.main([*rich, *argv]) == 0
    return [ln.rstrip() for ln in capsys.readouterr().out.splitlines()]


def test_host_detail_lines(capsys, rich):
    out = run(capsys, rich, "host", "H.EXAMPLE")
    assert (
        out[0]
        == "h.example  category=Cat  first=2026-10-25 12:00  last=2026-10-26 12:00  dns=3 tls=2 http=5  state=BLOCKED"
    )
    assert out[1] in ("rules seen in answers: r1, r2", "rules seen in answers: r2, r1")
    assert out[2:6] == [
        "TLS to: 9.9.9.9 x2, 8.8.8.8 x1",
        "flows to those IPs: up 31B down 302B",
        "plain HTTP requests: 2 (status 200..403)",
        "day         lookups  blocked",
    ]
    assert out[6:] == ["2026-10-25  1        0", "2026-10-26  2        2"]


def test_host_with_only_pcap_http_rows_still_lists_them(capsys, rich):
    c = db.connect(rich[1])
    c.execute("INSERT INTO hosts(name, first_seen, last_seen, category) VALUES ('p.example', 1, 2, 'Other')")
    c.execute(
        "INSERT INTO http(t, host, method, src) VALUES (1, 'p.example', 'GET', 'pcap')"
    )  # status is NULL
    c.commit()
    c.close()
    assert any(ln.startswith("plain HTTP requests: 1") for ln in run(capsys, rich, "host", "p.example"))


def test_host_not_seen_message(capsys, rich):
    assert cli.main([*rich, "host", "nobody.example"]) == 1
    assert capsys.readouterr().out == "not seen\n"


def test_retries_show_first_and_last_lookup(capsys, rich):
    out = run(capsys, rich, "retries", "2026-10-01")
    assert out[1].split() == [
        "ads.example",
        "2",
        "10-25",
        "12:00",
        "10-26",
        "12:00",
        "||ads^",
    ]  # first != last


def test_rules_show_removal_time(capsys, rich):
    out = run(capsys, rich, "rules")
    assert out[1:] == [
        "adguard  ||live^  2026-10-25 12:00",
        "adguard  ||old^   2026-10-25 12:00  2026-10-26 12:00",
    ]


def test_brief_json_is_indented_and_complete(capsys, rich):
    assert cli.main([*rich, "brief", "2026-10-26", "--json"]) == 0
    text = capsys.readouterr().out
    assert text.startswith('{\n "day": "2026-10-26",') and json.loads(text)["dns"]["blocked"] == 3


def test_brief_text_branches(capsys, rich):
    out = "\n".join(run(capsys, rich, "brief", "2026-10-26"))
    assert "URL filter: (no requests)" in out
    assert "Unexpected ports: TCP/80 -> 1.1.1.1 x1, UDP/9 -> 2.2.2.2 x1" in out
    assert "TV by hour: 12:00=?" in out
    removed_row = next(ln for ln in out.splitlines() if "||old^" in ln)
    assert removed_row.split()[-4:] == ["2026-10-25", "12:00", "2026-10-26", "12:00"]
    assert "||live^" not in out  # added and still active before the day: not a change on 2026-10-26


def test_empty_day_placeholders(capsys, rich):
    out = "\n".join(run(capsys, rich, "brief", "2020-01-01"))
    assert "URL filter: (no requests)" in out and "TV by hour: (no readings)" in out


def test_a_subcommand_is_required():
    with pytest.raises(SystemExit) as e:
        cli.main([])
    assert e.value.code == 2


def test_brief_day_is_optional_and_defaults_to_yesterday(capsys, rich, monkeypatch):
    monkeypatch.setattr(queries, "yesterday", lambda: "2026-10-26")
    assert cli.main([*rich, "brief", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["day"] == "2026-10-26"


def test_yesterday_is_the_previous_local_calendar_day():
    assert queries.yesterday() == (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")


def test_size_reports_megabytes(capsys, rich):
    out = run(capsys, rich, "size")
    assert 0 <= float(out[-1].split()[1]) < 5  # a tiny test store is a fraction of a megabyte, not 10**12


def test_adguard_diff_reports_drift_and_exits_1(capsys, gateway, tmp_path, monkeypatch):
    real_load = cli.config.load
    monkeypatch.setattr(
        cli.config, "load", lambda path, **kw: real_load(path, adguard_yaml=gateway.adguard_yaml, **kw)
    )
    assert cli.main(["--conf", str(tmp_path / "none.conf"), "adguard", "diff"]) == 1
    assert "filters.0.name: '<unset>' -> 'HaGeZi LG webOS'" in capsys.readouterr().out
