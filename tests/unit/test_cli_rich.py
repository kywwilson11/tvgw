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
        "INSERT INTO tls(t, dst, dport, sport, sni) VALUES (1000,?,443,?,'h.example')",
        [("9.9.9.9", 1), ("9.9.9.9", 2), ("8.8.8.8", 3)],
    )
    c.executemany(
        "INSERT INTO flows(t_start, t_end, dst, dport, sport, bytes_up, bytes_down) VALUES (990,1010,?,443,?,?,?)",
        [("9.9.9.9", 1, 10, 100), ("9.9.9.9", 2, 20, 200), ("8.8.8.8", 3, 1, 2)],
    )
    c.executemany("INSERT INTO http(t, host, status, src) VALUES (1,'h.example',?,'gfts')", [(200,), (403,)])
    c.executemany(
        "INSERT INTO rules(kind, text, first_seen, last_seen, removed_at) VALUES (?,?,?,?,?)",
        [("adguard", "||old^", D0, D0, D1), ("adguard", "||live^", D0, D1, None)],
    )
    c.executemany("INSERT INTO tvstate(t, power, app) VALUES (?,?,?)", [(D1, "Active", None)])
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
        "its connections: 3, up 31B down 302B",
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
    assert out[0].split() == ["blocked", "name", "lookups", "first", "last", "rule"]
    ads = next(ln for ln in out if ln.startswith("ads.example"))
    assert ads.split() == ["ads.example", "2", "10-25", "12:00", "10-26", "12:00", "||ads^"]  # first != last
    assert sorted(ln.split()[0] for ln in out[1:]) == ["ads.example", "h.example"]  # both asked twice
    h = next(ln for ln in out if ln.startswith("h.example")).split()
    assert h[:6] == ["h.example", "2", "10-26", "12:00", "10-26", "12:00"]  # both lookups on the same day


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
    assert "GFTS URL filter (status biz_code: requests):\n  (none)" in out
    assert "Unexpected ports: TCP/80 -> 1.1.1.1 x1, UDP/9 -> 2.2.2.2 x1" in out
    assert "LAN probes (dropped): none" in out
    assert "TV: 12:00=Active" in out
    removed_row = next(ln for ln in out.splitlines() if "||old^" in ln)
    assert removed_row.split()[-4:] == ["10-25", "12:00", "10-26", "12:00"]
    assert "||live^" not in out  # added and still active before the day: not a change on 2026-10-26
    # a store nothing has ingested yet: the brief says what it could not look at
    assert "NOT ASSESSED (source not read recently): flows, dns, pcaps, gfts, tvstate, oddport, verify" in out
    assert "Coverage: flows 0, dns 3, pcaps 0, gfts 0, tvstate 1, oddport 2, verify 0; last ingest -" in out
    assert "Allowed, outside the expected categories:\nname  category  lookups\n(none)" in out
    assert "Unresolved flows" not in out and "Firmware" not in out and "DNS oddities" not in out


def test_empty_day_placeholders(capsys, rich):
    out = "\n".join(run(capsys, rich, "brief", "2020-01-01"))
    assert "GFTS URL filter (status biz_code: requests):\n  (none)" in out
    assert out.endswith("TV: no readings")
    assert "Unexpected ports: none" in out and "New hosts (0):\nname" in out
    assert "Rule changes" not in out  # the section only exists when something changed


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


def full_brief():
    """A brief with every optional section populated, as queries.brief would hand it over."""
    t = parse_time("2026-10-26T09:30:00-05:00")
    src = ("flows", "dns", "pcaps", "gfts", "tvstate", "oddport")
    return {
        "day": "2026-10-26",
        "coverage": {
            "last_run": t,
            "warnings": ["dns: 2 malformed query-log record(s) skipped", "evil\x1b[2Jwarning"],
            "sources": {k: {"rows": i, "last_read": t, "assessed": k != "pcaps"} for i, k in enumerate(src)},
            "not_assessed": ["pcaps"],
        },
        "dns": {"lookups": 10, "blocked": 4, "names": 6},
        "flows": {"conns": 3, "bytes_up": 1536, "bytes_down": 3 * 1024**2},
        "new_hosts": [
            {"name": "a.example", "category": "Other", "dns": 1, "tls": 0, "http": 0, "blocked": 0},
            {
                "name": "b.example",
                "category": "Other",
                "dns": 1,
                "tls": 0,
                "http": 0,
                "blocked": None,
                "new_domain": False,
            },
        ],
        "blocked_retries": [],
        "allowed_unexpected": [{"name": "odd.example", "category": "Other", "lookups": 7}],
        "top_upload": [
            {
                "name": "up.example",
                "dst": "1.1.1.1",
                "ips": 3,
                "dport": 443,
                "conns": 5,
                "bytes_up": 2048,
                "bytes_down": 10,
            },
            {
                "name": None,
                "dst": "2.2.2.2",
                "ips": 1,
                "dport": 8443,
                "conns": 1,
                "bytes_up": 5,
                "bytes_down": 0,
            },
        ],
        "gfts": [{"status": 403, "biz_code": "MAS", "requests": 2, "bytes": 9}],
        "oddports": [],
        "lan_probes": [{"dst": f"192.168.8.{i}", "proto": "tcp", "dport": 80, "n": 1} for i in range(14)],
        "dns_anomalies": [
            {"kind": "long name", "name": "x.example", "lookups": 2, "blocked": 1, "detail": "120 chars"},
            {
                "kind": "fan-out",
                "name": "cdn.example",
                "lookups": 300,
                "blocked": None,
                "detail": "300 distinct names",
            },
        ],
        "must_allow_blocked": [],
        "clock": {"lookups": 4, "blocked": 1, "first": t, "hosts": ["*.lgtvsdp.com"]},
        "firewall": {
            "runs": 24,
            "failed": 1,
            "last_failure_t": t,
            "last_failures": ["FAIL x"],
            "activity": [
                {"rule": "DoT/DoQ block", "packets": 3},
                {"rule": "QUIC drop", "packets": 4},
                {"rule": "DoT/DoQ other", "packets": 2},
                {"rule": "an unlisted rule", "packets": 99},
            ],
        },
        "unresolved": [{"dst": "5.5.5.5", "dport": 443, "conns": 2, "bytes_up": 1024, "bytes_down": 0}],
        "ptr": {"lookups": 6, "names": 5},
        "firmware_changes": [
            {"t": t, "firmware": "04.65.10", "new_hosts": ["n1.example", "n2.example"]},
            {"t": t, "firmware": "04.65.20", "new_hosts": []},
        ],
        "standby": {"off_hours": 2, "lookups": 3, "conns": 1, "bytes_up": 2048},
        "tvstate": [{"time": "09:00", "power": "Active", "app": ""}],
        "rule_changes": [],
        "red_lines": ["must-allow name blocked: snu.lge.com x1 by ||lge.com^", "bad\x07line"],
    }


def test_render_brief_with_every_section(capsys):
    cli.render_brief(full_brief())
    got = [ln.rstrip() for ln in capsys.readouterr().out.splitlines()]
    assert got == EVERY_SECTION


EVERY_SECTION = """\
=== 2026-10-26: 10 lookups (4 blocked, 6 names), 3 connections, up 1.5K down 3.0M
Coverage: flows 0, dns 1, pcaps 2, gfts 3, tvstate 4, oddport 5; last ingest 10-26 09:30
NOT ASSESSED (source not read recently): pcaps
ingest warning: dns: 2 malformed query-log record(s) skipped
ingest warning: evil\\x1b[2Jwarning
RED LINE: must-allow name blocked: snu.lge.com x1 by ||lge.com^
RED LINE: bad\\x07line
Firewall held: DoT/DoQ 5, QUIC 4; 24 checks, 1 failed
Clock hosts: 4 lookups (1 blocked), first at 09:30
While off/asleep (2 h): 3 lookups, 1 connections, up 2.0K
Private reverse lookups (LAN inventory): 6 for 5 names

New hosts (2):
name       category  dns  tls  http  state
a.example  Other     1    0    0     allowed  new domain
b.example  Other     1    0    0     ?

Blocked and still retried:
name  lookups  rule
(none)

Allowed, outside the expected categories:
name         category  lookups
odd.example  Other     7

Top upload (per TLS name; IP when no hello was captured):
name           dst         port  conns  up    down
up.example     1.1.1.1 +2  443   5      2.0K  10B
(no TLS name)  2.2.2.2     8443  1      5B    0B

GFTS URL filter (status biz_code: requests):
  403 MAS: 2

Unexpected ports: none
LAN probes (dropped): 192.168.8.0:80 x1, 192.168.8.1:80 x1, 192.168.8.2:80 x1, 192.168.8.3:80 x1, 192.168.8.4:80 x1, 192.168.8.5:80 x1, 192.168.8.6:80 x1, 192.168.8.7:80 x1, 192.168.8.8:80 x1, 192.168.8.9:80 x1, 192.168.8.10:80 x1, 192.168.8.11:80 x1 +2 more

Unresolved flows (no DNS answer or TLS name explains the address):
dst      port  conns  up    down
5.5.5.5  443   2      1.0K  0B

Firmware 04.65.10 seen 10-26 09:30; new names in the 72 h after:
  n1.example, n2.example

Firmware 04.65.20 seen 10-26 09:30; new names in the 72 h after:
  (none yet)

DNS oddities:
kind       name         lookups  state    detail
long name  x.example    2        BLOCKED  120 chars
fan-out    cdn.example  300      ?        300 distinct names

TV: 09:00=Active
""".splitlines()
