"""(ports) `tvgw ports`: whether STRICT_PORTS and the clock port's narrowing have two clean weeks (design
decision 71).

A real store, written as `tvgw verify --record` and the hourly ingest leave it: counter snapshots every few
hours (the odd-port rule's count and the NTP count's set), the odd-port rule's samples, the TV's flows (the
days it was online) and its answers (the names of an address). Each verdict is read back: not counted,
not two weeks yet, an entry that blocks it, too few days online, ready, and the probation report once on."""

from __future__ import annotations

import json

import pytest
from conftest import NOW

from tvgw import cli, db, ports, queries
from tvgw.config import Settings

DAY = 86400
STRICT_OFF = "STRICT_PORTS=no: count only"
STRICT_ON = "STRICT_PORTS: only web, NTP and DNS"
CLOSED = "clock port: closed, NTP to no server"


@pytest.fixture
def conn(tmp_path):
    c = db.connect(str(tmp_path / "tvgw.db"))
    yield c
    c.close()


def snapshots(conn, start: float, end: float, rule: str, every: float = 6 * 3600, value=lambda t: 0):
    t = start
    while t < end:
        conn.execute("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,0)", (t, rule, value(t)))
        conn.execute("INSERT OR REPLACE INTO verify(t, ok, failures) VALUES (?, 1, '[]')", (t,))
        t += every


def ntp_count(conn, start: float, end: float, servers=None, every: float = 6 * 3600):
    """The NTP count's snapshots: its set row each time, and `servers` {address: (since, requests a step)}."""
    t, n = start, 0
    while t < end:
        held = {d: k * n for d, (since, k) in (servers or {}).items() if t >= since}
        rows = [(t, queries.NTP_SET_ROW, len(held), 1024), (t, queries.NTP_RULE, sum(held.values()), 0)]
        rows += [(t, f"{queries.NTP_SERIES}{d}", c, 800000) for d, c in held.items()]
        conn.executemany("INSERT INTO fw_counters(t, rule, packets, bytes) VALUES (?,?,?,?)", rows)
        conn.execute("INSERT OR REPLACE INTO verify(t, ok, failures) VALUES (?, 1, '[]')", (t,))
        t += every
        n += 1


def online(conn, days: list[int]):
    """A flow on each of the given days before NOW (0 is today)."""
    conn.executemany(
        "INSERT INTO flows(t_start, t_end, proto, dst, dport) VALUES (?,?,?,?,443)",
        [(NOW - d * DAY - 3600, NOW - d * DAY - 3000, "tcp", "203.0.113.80") for d in days],
    )


def odd(conn, t: float, dst: str = "203.0.113.5", dport: int = 5222, proto: str = "TCP"):
    conn.execute("INSERT INTO oddport(t, proto, dst, dport, raw) VALUES (?,?,?,?,'')", (t, proto, dst, dport))


def answer(conn, t: float, name: str, addr: str):
    conn.execute(
        "INSERT INTO dns(t, qname, qtype, answers, blocked) VALUES (?, ?, 'A', ?, 0)", (t, name, f"A:{addr}")
    )


# ---- unusual ports ---------------------------------------------------------------------------------------


def test_with_no_count_there_is_nothing_to_judge(conn):
    r = ports.strict_readiness(conn, NOW, "no")
    assert r.state == ports.NOT_COUNTED and "Not counted yet" in r.line and r.how == []


def test_a_count_shorter_than_two_weeks_says_when_they_end(conn):
    snapshots(conn, NOW - 5 * DAY, NOW, STRICT_OFF)
    online(conn, range(5))
    r = ports.strict_readiness(conn, NOW, "no")
    assert r.state == ports.WAITING and r.due == pytest.approx(NOW + 9 * DAY)
    assert r.line == (
        "Not ready yet: the count started on 21 October, and its 14 days end on 4 November. No unusual port"
        " so far."
    )


def test_two_clean_weeks_with_the_tv_online_are_ready_on_probation(conn):
    snapshots(conn, NOW - 20 * DAY, NOW, STRICT_OFF)
    online(conn, range(0, 14, 1))
    r = ports.strict_readiness(conn, NOW, "no")
    assert r.state == ports.READY and r.counted == 0 and r.online_days == 14
    assert r.line == (
        "Ready to refuse on probation: no unusual port in the 14 days to 26 October (the TV was online on 14"
        " of them)."
    )
    assert r.how[0].startswith(
        "To switch: set STRICT_PORTS=yes in /etc/tvgw/tvgw.conf, then run sudo tvgw-apply."
    )
    assert "To undo it: set STRICT_PORTS=no" in r.how[1]


def test_a_tv_that_was_mostly_off_is_too_few_days_to_tell(conn):
    snapshots(conn, NOW - 20 * DAY, NOW, STRICT_OFF)
    online(conn, [1, 2, 3])
    r = ports.strict_readiness(conn, NOW, "no")
    assert r.state == ports.WAITING and "online on only 3 of the last 14 days" in r.line


def test_an_unusual_port_blocks_it_names_the_destination_and_says_when_the_clean_run_could_end(conn):
    snapshots(conn, NOW - 20 * DAY, NOW, STRICT_OFF, value=lambda t: 0 if t < NOW - 3 * DAY else 4)
    online(conn, range(14))
    odd(conn, NOW - 3 * DAY + 60)
    odd(conn, NOW - 3 * DAY + 120)
    odd(conn, NOW - 30 * DAY, dport=9999)  # before the window: not listed
    answer(conn, NOW - 3 * DAY, "chat.example.net", "203.0.113.5")
    r = ports.strict_readiness(conn, NOW, "no")
    assert r.state == ports.BLOCKED and r.counted == 4
    assert r.due == pytest.approx(NOW - 3 * DAY + 120 + 14 * DAY)
    assert r.line == (
        "Not ready: the TV made 4 connection attempts to unusual ports in the last 14 days, the last on 23"
        " October. 14 clean days would end on 6 November if no other comes."
    )
    assert r.rows == [
        {
            "proto": "tcp",
            "dport": 5222,
            "dst": "203.0.113.5",
            "samples": 2,
            "first": NOW - 3 * DAY + 60,
            "last": NOW - 3 * DAY + 120,
            "name": "chat.example.net",
        }
    ]


def test_the_counter_alone_blocks_it_when_the_log_lost_the_samples(conn):
    snapshots(conn, NOW - 20 * DAY, NOW, STRICT_OFF, value=lambda t: 0 if t < NOW - 2 * DAY else 1)
    online(conn, range(14))
    r = ports.strict_readiness(conn, NOW, "no")
    assert r.state == ports.BLOCKED and r.counted == 1 and r.rows == []


def test_once_on_it_is_the_probation_report(conn):
    snapshots(conn, NOW - 20 * DAY, NOW - 6 * DAY, STRICT_OFF)
    snapshots(conn, NOW - 6 * DAY, NOW, STRICT_ON, value=lambda t: 0 if t < NOW - DAY else 2)
    r = ports.strict_readiness(conn, NOW, "yes")
    assert r.state == ports.ON and r.refused == 2
    assert r.line == (
        "STRICT_PORTS=yes since 20 October, on probation: it refused 2 connection attempts to unusual ports"
        " in the last 14 days."
    )
    assert "sudo tvgw refused" in r.how[0] and "STRICT_PORTS=no" in r.how[1]


# ---- the clock port --------------------------------------------------------------------------------------


def test_the_clock_count_before_its_two_weeks_says_when_they_end(conn):
    ntp_count(conn, NOW - 2 * DAY, NOW)
    online(conn, [0, 1])
    r = ports.clock_readiness(conn, NOW, None, "any")
    assert r.state == ports.WAITING and r.counted == 0
    assert r.line == (
        "Not ready yet: the clock-server count started on 24 October, and its 14 days end on 7 November. So"
        " far the TV sent NTP to no server."
    )


def test_two_weeks_without_ntp_are_ready_to_close(conn, lg):
    ntp_count(conn, NOW - 16 * DAY, NOW)
    online(conn, range(10))
    r = ports.clock_readiness(conn, NOW, lg, "any")
    assert r.state == ports.READY
    assert r.line == (
        "Ready to close on probation: the TV sent NTP to no server in the 14 days to 26 October (it was online"
        " on 10 of them)."
    )
    assert r.how[0].startswith("To switch: set CLOCK_PORT=none in /etc/tvgw/tvgw.conf")


def test_a_server_no_lookup_named_blocks_closing_and_narrowing(conn):
    ntp_count(conn, NOW - 16 * DAY, NOW, {"203.0.113.9": (NOW - 4 * DAY, 2)})
    online(conn, range(10))
    r = ports.clock_readiness(conn, NOW, None, "any")
    assert r.state == ports.BLOCKED and r.counted > 0
    assert "203.0.113.9 among them, which no lookup of the TV's named" in r.line
    assert r.rows[0]["dst"] == "203.0.113.9" and not r.rows[0]["named"]


def test_servers_each_a_lookup_named_point_at_resolved(conn):
    ntp_count(conn, NOW - 16 * DAY, NOW, {"203.0.113.9": (NOW - 4 * DAY, 1)})
    answer(conn, NOW - DAY, "time.example.net", "203.0.113.9")
    online(conn, range(10))
    r = ports.clock_readiness(conn, NOW, None, "any")
    assert r.state == ports.BLOCKED and r.rows[0]["names"] == ["time.example.net"]
    assert (
        "each one a lookup of the TV's named" in r.line
        and "ntp = resolved would keep these servers" in r.line
    )


def test_with_no_ntp_count_it_says_how_to_start_one(conn):
    r = ports.clock_readiness(conn, NOW, None, "any")
    assert r.state == ports.NOT_COUNTED and "sudo tvgw-apply loads it" in r.line


def test_once_closed_it_is_the_probation_report(conn):
    snapshots(conn, NOW - 3 * DAY, NOW, CLOSED, value=lambda t: 0 if t < NOW - DAY else 3)
    r = ports.clock_readiness(conn, NOW, None, "none")
    assert r.state == ports.ON and r.refused == 3
    assert r.line == "The clock port is closed, on probation: it refused 3 NTP requests in the last 14 days."


# ---- what is in force, the command -----------------------------------------------------------------------


def test_what_is_in_force_comes_from_the_last_apply_else_the_settings():
    s = Settings()
    assert ports.in_force(s, {}) == ("no", "any", "the profile's [firewall] ntp")
    applied = {
        "STRICT_PORTS": "yes",
        "CLOCK_PORT": "profile",
        "CLOCK_PORT_PROFILE": "none",
        "CLOCK_PORT_USED": "none",
    }
    assert ports.in_force(s, applied) == ("yes", "none", "the profile's [firewall] ntp = none")
    unread = {"CLOCK_PORT": "profile", "CLOCK_PORT_PROFILE": "unread", "CLOCK_PORT_USED": "any"}
    assert ports.in_force(s, unread)[2] == "the profile's [firewall] ntp could not be read at the last apply"
    assert ports.in_force(s, {"CLOCK_PORT": "none", "CLOCK_PORT_USED": "any"})[1:] == (
        "any",
        "CLOCK_PORT=none",
    )
    assert ports.in_force(Settings(clock_port="none"), {}) == ("no", "none", "CLOCK_PORT=none")


def test_the_command_prints_both_walls_and_changes_nothing(tmp_path, monkeypatch, capsys, lg):
    path = tmp_path / "tvgw.db"
    c = db.connect(str(path))
    snapshots(c, NOW - 20 * DAY, NOW, STRICT_OFF)
    ntp_count(c, NOW - 2 * DAY, NOW)
    online(c, range(14))
    c.commit()
    c.close()
    applied = tmp_path / "settings.applied"
    applied.write_text("STRICT_PORTS=no\nCLOCK_PORT=profile\nCLOCK_PORT_PROFILE=any\nCLOCK_PORT_USED=any\n")
    monkeypatch.setattr(cli, "APPLIED", str(applied))
    before = path.read_bytes()
    conf = tmp_path / "tvgw.conf"
    conf.write_text("")
    assert cli.main(["--conf", str(conf), "--db", str(path), "ports"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "Unusual ports (STRICT_PORTS=no; counted since 6 October):"
    assert out[1].startswith("  Ready to refuse on probation: no unusual port in the 14 days to 26 October")
    clock = out.index(
        "Clock port (NTP open to any server, as the profile's [firewall] ntp = any says; counted since 24 October):"
    )
    assert out[clock + 1].startswith("  Not ready yet: the clock-server count started on 24 October")
    assert out[-1] == "tvgw ports read the gateway's own record; it changed nothing."
    assert path.read_bytes() == before
    assert cli.main(["--conf", str(conf), "--db", str(path), "ports", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [w["wall"] for w in doc["walls"]] == ["strict", "clock"]
    assert [w["state"] for w in doc["walls"]] == ["ready", "waiting"]


def test_ntp_seen_is_what_the_apply_reads_before_it_closes_the_clock_port(tmp_path, capsys):
    """(review B2) The record the kernel's count cannot keep across a reboot: the TV's NTP requests the store
    holds for the last 14 days. No store at all is no record; one that cannot be opened is an error."""
    conf = tmp_path / "tvgw.conf"
    conf.write_text("")
    path = tmp_path / "tvgw.db"
    assert cli.main(["--conf", str(conf), "--db", str(path), "ports", "--ntp-seen"]) == 0
    assert capsys.readouterr().out == "ntp_requests=0\nntp_record=none\n" and not path.exists()
    c = db.connect(str(path))
    ntp_count(c, NOW - 3 * DAY, NOW, {"203.0.113.9": (NOW - 2 * DAY, 2)})
    c.commit()
    c.close()
    assert cli.main(["--conf", str(conf), "--db", str(path), "ports", "--ntp-seen"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[1] == "ntp_record=counted" and int(out[0].split("=")[1]) > 0
    path.write_bytes(b"not a store")
    with pytest.raises(SystemExit) as stop:
        cli.main(["--conf", str(conf), "--db", str(path), "ports", "--ntp-seen"])
    assert stop.value.code not in (0, None)
