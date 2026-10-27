"""Golden output of every read-only subcommand on the fake gateway: pins which column shows what."""

import io
import re
import time

import pytest
from conftest import fake_extract, fake_oddport

from tvgw import cli, db, ingest, queries

NOW = 1793026800.0  # 2026-10-26 10:00 CDT


@pytest.fixture()
def conf(gateway, lg, tmp_path, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: NOW)  # rule history is stamped with the ingest time
    ingest.run(gateway, lg, extract=fake_extract, oddport_lines=fake_oddport, lock=False)
    path = tmp_path / "tvgw.conf"
    path.write_text(f'TV_IP={gateway.tv_ip}\nDB_PATH="{gateway.db_path}"\nDB_DAYS=30\n')
    return path


def lines(text: str) -> list[str]:
    return [ln.rstrip() for ln in text.rstrip("\n").split("\n")]


GOLDEN = [
    (
        ["new-hosts", "2026-10-26"],
        """\
name                          category  first seen        dns  tls  http  state    rule
gfts.lge.com                  LG core   2026-10-26 08:08  0    1    0     ?
ngfts.lge.com                 LG core   2026-10-26 08:08  0    0    3     ?
us.lgtvsdp.com                LG core   2026-10-26 09:14  1    0    0     allowed  @@||us.lgtvsdp.com^
aic.recommend.lgtvcommon.com  LG ads    2026-10-26 09:14  1    0    0     BLOCKED  ||recommend.lgtvcommon.com^
""",
    ),
    (
        ["retries", "2026-10-26"],
        """\
blocked name                  lookups  first        last         rule
aic.recommend.lgtvcommon.com  1        10-26 09:14  10-26 09:14  ||recommend.lgtvcommon.com^
""",
    ),
    (
        ["allowed", "2026-10-26"],
        """\
allowed name (non-streaming)  lookups  last         allow rule
us.lgtvsdp.com                1        10-26 09:14  @@||us.lgtvsdp.com^
""",
    ),
    (
        ["top-upload", "2026-10-26"],
        """\
name           dst                conns  up    down
(no TLS name)  142.251.219.1:443  1      2.2K  10.5K
(no TLS name)  10.10.10.1:53      1      64B   145B
""",
    ),
    (
        ["gfts", "2026-10-26"],
        """\
status  biz_code   requests  bytes
200     APP_STORE  1         6.3K
403     PREMIUM    1         153B
""",
    ),
    (
        ["tvstate", "2026-10-26"],
        """\
time              power        app
2026-10-26 08:20  unreachable
2026-10-26 09:19  Active       youtube.leanback.v4
settings changes:
time              key              value
2026-10-26 09:19  option.livePlus  off
2026-10-26 09:19  option.zipcode   10001
""",
    ),
    (
        ["rules"],
        """\
kind        rule                                               since             removed
adguard     @@||us.lgtvsdp.com^                                2026-10-26 10:00
adguard     ||alphonso.tv^                                     2026-10-26 10:00
adguard     ||ngfts.lge.com^$dnsrewrite=10.10.10.1             2026-10-26 10:00
block4      203.0.113.9                                        2026-10-26 10:00
gfts-block  biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)  2026-10-26 10:00
""",
    ),
    (
        ["host", "gfts.lge.com"],
        """\
gfts.lge.com  category=LG core  first=2026-10-26 08:08  last=2026-10-26 08:08  dns=0 tls=1 http=0  state=?
rules seen in answers: (none)
TLS to: 23.5.6.43 x1
flows to those IPs: up 0B down 0B
day  lookups  blocked
(none)
""",
    ),
    (
        ["host", "aic.recommend.lgtvcommon.com"],
        """\
aic.recommend.lgtvcommon.com  category=LG ads  first=2026-10-26 09:14  last=2026-10-26 09:14  dns=1 tls=0 http=0  state=BLOCKED
rules seen in answers: ||recommend.lgtvcommon.com^
day         lookups  blocked
2026-10-26  1        1
""",
    ),
]


@pytest.mark.parametrize(("argv", "expected"), GOLDEN, ids=lambda v: v[0] if isinstance(v, list) else "")
def test_subcommand_output(conf, capsys, argv, expected):
    assert cli.main(["--conf", str(conf), *argv]) == 0
    assert lines(capsys.readouterr().out) == lines(expected)


BRIEF_HEAD = """\
=== 2026-10-26: 2 lookups (1 blocked, 2 names), 2 connections, up 2.3K down 10.6K

New hosts (4):
name                          category  dns  tls  http  state
gfts.lge.com                  LG core   0    1    0     ?
ngfts.lge.com                 LG core   0    0    3     ?
us.lgtvsdp.com                LG core   1    0    0     allowed
aic.recommend.lgtvcommon.com  LG ads    1    0    0     BLOCKED

Blocked and still retried:
name                          lookups  rule
aic.recommend.lgtvcommon.com  1        ||recommend.lgtvcommon.com^

Allowed, non-streaming:
name            lookups
us.lgtvsdp.com  1

Top upload:
name           dst                conns  up    down
(no TLS name)  142.251.219.1:443  1      2.2K  10.5K
(no TLS name)  10.10.10.1:53      1      64B   145B

URL filter: 200 APP_STORE: 1 (6.3K), 403 PREMIUM: 1 (153B)
Unexpected ports: TCP/8080 -> 156.147.69.32 x1
TV by hour: 08:20=unreachable 09:19=Active
Rule changes:"""

BRIEF_RULES = """\
kind        rule                                               added             removed
adguard     @@||us.lgtvsdp.com^                                2026-10-26 10:00
adguard     ||alphonso.tv^                                     2026-10-26 10:00
adguard     ||ngfts.lge.com^$dnsrewrite=10.10.10.1             2026-10-26 10:00
block4      203.0.113.9                                        2026-10-26 10:00
gfts-block  biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)  2026-10-26 10:00"""


def test_brief_text(conf, gateway):
    out = io.StringIO()
    cli.render_brief(queries.brief(db.connect(gateway.db_path, readonly=True), "2026-10-26"), out)
    head, _, rules = out.getvalue().partition("Rule changes:\n")
    assert lines(head + "Rule changes:") == lines(BRIEF_HEAD)
    got = lines(rules)  # brief() has no ORDER BY on rule_changes, so compare the body as a set of rows
    assert got[0] == lines(BRIEF_RULES)[0] and sorted(got[1:]) == sorted(lines(BRIEF_RULES)[1:])


def test_size_output(conf, capsys):
    assert cli.main(["--conf", str(conf), "size"]) == 0
    out = lines(capsys.readouterr().out)
    assert out[:10] == [
        "flows               2",
        "dns                 2",
        "tls                 1",
        "http                3",
        "tvstate             2",
        "tvsettings          2",
        "oddport             1",
        "hosts               4",
        "rules               5",
        "pcaps_done          1",
    ]
    assert out[10] == "oldest dns row: 2026-10-26 09:14" and re.fullmatch(r"file: \d+\.\d MB", out[11])


@pytest.mark.parametrize(
    "query", ["SELECT 1 AS one", "  select 1", "with x as (select 1) select * from x", "pragma user_version"]
)
def test_sql_accepts_read_only_statements_in_any_case(conf, capsys, query):
    assert cli.main(["--conf", str(conf), "sql", *query.split(" ")]) == 0


@pytest.mark.parametrize(
    "query", ["delete from dns", "insert into meta values ('a','b')", "selection 1", "drop table dns"]
)
def test_sql_rejects_everything_else(conf, query):
    with pytest.raises(SystemExit, match="read-only"):
        cli.main(["--conf", str(conf), "sql", *query.split(" ")])


@pytest.mark.parametrize(
    ("n", "text"),
    [
        (0, "0B"),
        (1023, "1023B"),
        (1024, "1.0K"),
        (1536, "1.5K"),
        (1024**2 - 1, "1024.0K"),
        (1024**2, "1.0M"),
        (5 * 1024**3, "5.0G"),
        (2048 * 1024**3, "2048.0G"),
        (None, "0B"),
    ],
)
def test_hb_unit_boundaries(n, text):
    assert cli.hb(n) == text


def test_ts_and_state_word_edges():
    assert cli.ts(None) == "-" and cli.ts(0) == "-"
    assert cli.ts(NOW) == "10-26 10:00" and cli.ts(NOW, "%Y") == "2026"
