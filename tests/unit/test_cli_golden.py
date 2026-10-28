"""Golden output of every read-only subcommand on the fake gateway: pins which column shows what."""

import io
import json
import os
import pathlib
import re
import shutil
import types

import pytest
from conftest import NOW, fake_extract, fake_oddport

from tvgw import cli, config, db, ingest, queries


@pytest.fixture()
def conf(gateway, lg, tmp_path):
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
allowed name (unexpected category)  category  lookups  last  allow rule
(none)
""",
    ),
    (
        ["top-upload", "2026-10-26"],
        """\
name           dst            port  conns  up    down
(no TLS name)  142.251.219.1  443   1      2.2K  10.5K
(no TLS name)  10.10.10.1     53    1      64B   145B
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
adguard     @@||us.lgtvsdp.com^$important                      2026-10-26 10:00
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
its connections: 0, up 0B down 0B
day  lookups  blocked
(none)
""",
    ),
    (
        ["host", "ngfts.lge.com"],
        """\
ngfts.lge.com  category=LG core  first=2026-10-26 08:08  last=2026-10-26 09:15  dns=0 tls=0 http=3  state=?
rules seen in answers: (none)
plain HTTP requests: 3 (status 200..403)
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


BRIEF = """\
=== 2026-10-26: 2 lookups (1 blocked, 2 names), 2 connections, up 2.3K down 10.6K
Coverage: flows 2, dns 2, pcaps 1, gfts 2, tvstate 2, oddport 1, verify 0; last ingest 10-26 10:00
NOT ASSESSED (source not read recently): verify
Firewall held: no counter snapshots yet; no checks recorded
Clock hosts: 1 lookups (0 blocked), first at 09:14

By category:
category    lookups  blocked  names  conns  up    down 
LG ads      1        1        1      0      0B    0B   
LG core     1        0        1      0      0B    0B   
Unresolved  0        0        0      1      2.2K  10.5K
Gateway     0        0        0      1      64B   145B 

New hosts (4):
name                          category  dns  tls  http  state              
gfts.lge.com                  LG core   0    1    0     ?        new domain
ngfts.lge.com                 LG core   0    0    3     ?                  
us.lgtvsdp.com                LG core   1    0    0     allowed  new domain
aic.recommend.lgtvcommon.com  LG ads    1    0    0     BLOCKED  new domain

Blocked and still retried:
name                          lookups  rule                       
aic.recommend.lgtvcommon.com  1        ||recommend.lgtvcommon.com^

Allowed, outside the expected categories:
name  category  lookups
(none)

Top upload (per TLS name; IP when no hello was captured; payload<= strips 40 B of headers per packet):
name           dst            port  conns  up    payload<=  down 
(no TLS name)  142.251.219.1  443   1      2.2K  1.5K       10.5K

GFTS URL filter (status biz_code: requests):
  200 APP_STORE: 1, 403 PREMIUM: 1

Unexpected ports: TCP/8080 -> 156.147.69.32 x1
LAN probes (dropped): 192.168.8.69:80 x1

Unresolved flows (no DNS answer or TLS name explains the address):
dst            port  conns  up    down 
142.251.219.1  443   1      2.2K  10.5K

TV: 08:20=unreachable, 09:19=Active

TV settings (first reading or change):
time         key              value
10-26 09:19  option.livePlus  off
10-26 09:19  option.zipcode   10001

Rule changes:
kind        rule                                               added        removed
adguard     @@||us.lgtvsdp.com^$important                      10-26 10:00         
adguard     ||alphonso.tv^                                     10-26 10:00         
adguard     ||ngfts.lge.com^$dnsrewrite=10.10.10.1             10-26 10:00         
block4      203.0.113.9                                        10-26 10:00         
gfts-block  biz_code=(PREMIUM|CDP|LGSHOPPING|MAS|IBS)([&_]|$)  10-26 10:00         
"""


def test_brief_text(conf, gateway, lg):
    out = io.StringIO()
    cli.render_brief(queries.brief(db.connect(gateway.db_path, readonly=True), "2026-10-26", lg), out)
    if os.environ.get(
        "TVGW_GOLDEN_OUT"
    ):  # regenerate: TVGW_GOLDEN_OUT=/path pytest -k brief_text, then review
        pathlib.Path(os.environ["TVGW_GOLDEN_OUT"]).write_text(out.getvalue())
    assert lines(out.getvalue()) == lines(BRIEF)  # rule changes come ordered by first_seen, kind, text


def test_brief_json_is_the_same_data(conf, capsys):
    assert cli.main(["--conf", str(conf), "brief", "2026-10-26", "--json"]) == 0
    o = json.loads(capsys.readouterr().out)
    assert o["day"] == "2026-10-26" and o["dns"] == {"lookups": 2, "blocked": 1, "names": 2}
    assert o["lan_probes"] == [{"dst": "192.168.8.69", "proto": "tcp", "dport": 80, "n": 1}]
    assert o["red_lines"] == [] and o["coverage"]["not_assessed"] == ["verify"]  # the fixture never ran it


def test_size_output(conf, capsys):
    assert cli.main(["--conf", str(conf), "size"]) == 0
    out = lines(capsys.readouterr().out)
    assert out[:14] == [
        "flows               2",
        "dns                 2",
        "tls                 1",
        "http                4",  # two pcap requests (one of them SSDP) and two gfts log lines
        "lanprobe            1",
        "tvstate             2",
        "tvsettings          2",
        "oddport             1",
        "hosts               4",
        "rules               5",
        "verify              0",
        "fw_counters         0",
        "pcaps_done          1",
        "ingest_runs         1",
    ]
    assert out[14] == "oldest dns row: 2026-10-26 09:14" and re.fullmatch(r"file: \d+\.\d MB", out[15])


def test_prune_pcaps_on_the_fixture_deletes_nothing_and_says_so(conf, gateway, capsys, monkeypatch):
    """Both files are young and far under budget, and one is the live file. The conf file has no key for
    the pcap directory (the shell side fixes it), so the loaded settings are the fixture's."""
    monkeypatch.setattr(config, "load", lambda path, **overrides: gateway)
    monkeypatch.setattr(shutil, "disk_usage", lambda path: types.SimpleNamespace(free=1 << 40))
    assert cli.main(["--conf", str(conf), "prune-pcaps"]) == 0
    out = capsys.readouterr()
    assert lines(out.out) == ["tvgw prune-pcaps: deleted 0, kept 2 (0 MB)"] and out.err == ""
    assert sorted(os.listdir(gateway.pcap_dir)) == ["tv-20261026-0800.pcap", "tv-20261026-0900.pcap"]


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


def test_sql_errors_are_reported_not_raised(conf):
    with pytest.raises(SystemExit, match=r"^sql: no such table: nope"):
        cli.main(["--conf", str(conf), "sql", "select", "*", "from", "nope"])


def test_sql_cannot_write_even_through_a_select_prefix(conf):
    with pytest.raises(SystemExit, match=r"^sql: "):
        cli.main(["--conf", str(conf), "sql", "with", "x", "as", "(select 1)", "delete", "from", "dns"])


def test_sql_prints_a_table_and_escapes_control_characters(conf, capsys):
    assert cli.main(["--conf", str(conf), "sql", "select 'a' || char(27) || '[2Jb' as v, 2 as n"]) == 0
    assert lines(capsys.readouterr().out) == ["v          n", "a\\x1b[2Jb  2"]


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
