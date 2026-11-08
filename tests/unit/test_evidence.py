"""(evidence) `tvgw evidence`, design decision 75: the local file of each day's facts, chained line to line
by SHA-256. What a day line holds (and what it never holds: an address of the home, a time of day, a full
host name), that a run only ever appends settled days, that every kind of tampering short of the last
line breaks the chain, that a broken chain is never appended to, and the command's exit codes."""

import json
import os
import random
import stat
import time

import acr_synth as synth
import pytest
from appfront_store import DAY, H0, HOUR, YT, Store, evening

from tvgw import cli, evidence, forget

NOW = H0 + 20 * DAY + 12 * HOUR  # 2026-11-15 noon: 2026-11-14 has settled


def runs(store: Store, a: float, b: float, warnings: list[str] | None = None) -> None:
    """The hourly ingest's runs at 20 minutes past each hour in [a, b), each with `warnings`."""
    t = a - a % HOUR + 20 * 60
    rows = []
    while t < b:
        if t >= a:
            rows.append((t, json.dumps(warnings or [])))
        t += HOUR
    store.conn.executemany("INSERT OR REPLACE INTO ingest_runs(t, seconds, warnings) VALUES (?, 1, ?)", rows)
    store.conn.commit()


@pytest.fixture()
def store(tmp_path):
    """A store whose hourly ingest ran every hour from H0 to 23 days later."""
    s = Store(tmp_path / "tvgw.db")
    runs(s, H0, H0 + 23 * DAY)
    yield s
    s.conn.close()


def setting(store: Store, t: float, key: str, value: str) -> None:
    store.conn.execute("INSERT INTO tvsettings(t, key, value) VALUES (?, ?, ?)", (t, key, value))
    store.conn.commit()


def busy_day(store: Store, day: int) -> None:
    """A day with refused trackers, one reached, an ACR-shaped hour and a telemetry upload."""
    t = evening(day, 20)
    store.reading(t, "Active", YT)
    store.lookup(t, "tkacr601.alphonso.tv", blocked=1)
    store.lookup(t + 1, "tkacr602.alphonso.tv", blocked=1)
    store.lookup(t + 2, "ads.doubleclick.net", blocked=1)
    store.lookup(t + 3, "mrm.fwmrm.net")
    store.talk(t + 3.5, "mrm.fwmrm.net", up_=5_000, down_=1_000)


def write(store: Store, path: str, now: float = NOW, days: int = 30) -> evidence.Written:
    return evidence.append(path, store.conn, _lg(), now, days, "0.0.0-test", record_from=H0)


def _lg():
    from tvgw import profile

    return profile.load("lg-webos")


def text_of(path: str) -> str:
    with open(path, encoding="ascii", newline="") as f:
        return f.read()


def lines_of(path: str) -> list[str]:
    return text_of(path).split("\n")[:-1]


# ---- what a day line holds ---------------------------------------------------------------------------
def test_a_day_line_names_trackers_by_domain_and_keeps_attempted_reached_and_estimated_apart(store, lg):
    busy_day(store, 3)
    setting(store, H0, "model", "OLED55CX5LB")
    setting(store, H0, "firmware", "04.64.00")
    setting(store, H0, "option.livePlus", "off")
    setting(store, H0, "eula.acrAllowed", "false")
    setting(store, evening(3, 12), "eula.acrAllowed", "true")  # accepted on the TV that day
    rng = random.Random(1)
    synth.insert(store.conn, synth.imc_fingerprint_hour(rng, evening(3, 21)))
    synth.insert(store.conn, synth.telemetry_burst(rng, evening(3, 14)))
    facts = evidence.day_facts(store.conn, lg, "2026-10-29")
    assert facts["tv"] == {"model": "OLED55CX5LB", "firmware": "04.64.00"}
    assert facts["consent"] == {
        "live_plus": "off",
        "flags": {"acrAllowed": "true"},
        "accepted_this_day": ["acrAllowed"],
    }
    by = {t["domain"]: t for t in facts["trackers"]}
    assert by["alphonso.tv"]["refused_lookups"] == 2 and by["alphonso.tv"]["company"] == "LG Group"
    assert by["alphonso.tv"]["category"] == "ACR"
    assert by["alphonso.tv"]["connections"] == 60  # the fingerprint hour, reached by its hellos
    assert by["fwmrm.net"]["answered_lookups"] == 1 and by["fwmrm.net"]["connections"] == 1
    assert by["fwmrm.net"]["net_up"] == 4_000 - 0  # 5,000 up, 1,000 down, 10 packets each way
    assert by["doubleclick.net"]["connections"] == 0
    assert [f["destination"] for f in facts["acr_test"]][:1] == ["alphonso.tv"]
    over = facts["uploads_over_budget"]
    assert over["source"] == "floor" and "example.com" in {o["destination"] for o in over["over"]}
    assert facts["record"]["lookups"] == 4 and facts["record"]["tv_readings"] == 1
    assert facts["summary"].startswith("The filter refused 3 lookups of 2 tracking domains;")
    assert "ACR consent flags true: acrAllowed" in facts["summary"]


def test_a_day_the_gateway_saw_nothing_says_so(store, lg):
    facts = evidence.day_facts(store.conn, lg, "2026-10-30")
    assert facts["summary"] == "The gateway recorded no lookup and no connection of the TV this day."
    assert facts["record"] == {
        "lookups": 0,
        "connections": 0,
        "named_share": None,
        "tv_readings": 0,
        "ingest_runs": 24,
    }


def walk(value):
    if isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from walk(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk(v)
    else:
        yield value


def test_the_file_holds_no_home_address_no_time_of_day_and_no_full_host_name(store, tmp_path):
    for day in range(10):
        busy_day(store, day)
    path = str(tmp_path / "ev" / evidence.NAME)
    write(store, path)
    text = text_of(path)
    assert "10.10.10." not in text and "tkacr6" not in text and "mrm.fwmrm.net" not in text
    for line in lines_of(path)[1:]:
        keys = set(walk(json.loads(line)))
        assert not keys & {"t", "hour", "time", "app", "start", "end"}


# ---- appending -----------------------------------------------------------------------------------------
def test_a_run_appends_the_settled_days_once_and_never_rewrites_a_line(store, tmp_path):
    for day in range(20):
        busy_day(store, day)
    path = str(tmp_path / "ev" / evidence.NAME)
    first = write(store, path, days=5)
    assert first.created and first.days == [
        "2026-11-10",
        "2026-11-11",
        "2026-11-12",
        "2026-11-13",
        "2026-11-14",
    ]
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700
    before = lines_of(path)
    assert json.loads(before[0])["kind"] == "header" and json.loads(before[0])["prev"] == evidence.GENESIS
    again = write(store, path, days=5)
    assert again.days == [] and again.head == first.head and lines_of(path) == before
    # a wider window reaches back no further than the file's newest day, and nothing above it changes
    later = write(store, path, now=NOW + 2 * DAY, days=30)
    assert later.days == ["2026-11-15", "2026-11-16"] and later.total == 7
    assert lines_of(path)[: len(before)] == before
    v = evidence.verify(path)
    assert v.ok and v.head == later.head == evidence.digest(lines_of(path)[-1])
    assert v.days[0] == "2026-11-10" and len(v.days) == 7


def test_a_day_still_settling_and_the_days_before_the_record_are_not_written(store, tmp_path):
    path = str(tmp_path / evidence.NAME)
    # 01:00 on 2026-11-15: yesterday ended an hour ago, under SETTLE
    early = H0 + 20 * DAY + HOUR
    done = evidence.append(path, store.conn, _lg(), early, 30, "t", record_from=H0)
    assert done.days[0] == "2026-10-26" and done.days[-1] == "2026-11-13"
    assert evidence.due_days(None, NOW, 30, None) == []


def test_a_day_the_record_does_not_cover_is_left_out_and_says_why(store, tmp_path):
    """A day with a loss warning, a day the ingest never ran in (the Pi off, or a clock stepped past it)
    and a day whose settled run has not come yet are not written; the days around them are."""
    a = queries_day("2026-11-10")  # its runs from 04:00 gone, one at 10:20 warning of lost lines
    store.conn.execute("DELETE FROM ingest_runs WHERE t >= ? AND t < ?", (a + 4 * HOUR, a + DAY))
    runs(store, a + 10 * HOUR, a + 11 * HOUR, ["flows: 12 malformed line(s) skipped"])
    b = queries_day("2026-11-12")
    store.conn.execute("DELETE FROM ingest_runs WHERE t >= ? AND t < ?", (b, b + DAY))
    store.conn.commit()
    path = str(tmp_path / evidence.NAME)
    done = write(store, path, days=6)
    assert done.days == ["2026-11-09", "2026-11-11", "2026-11-13", "2026-11-14"]
    assert dict(done.left_out) == {
        "2026-11-10": "the hourly ingest warned: flows: 12 malformed line(s) skipped",
        "2026-11-12": "the hourly ingest did not run during it",
    }
    # the day after the newest run that came SETTLE after it waits for that run
    store.conn.execute("DELETE FROM ingest_runs WHERE t >= ?", (queries_day("2026-11-15") + 2 * HOUR,))
    store.conn.commit()
    later = write(store, path, now=NOW + DAY)
    assert later.days == [] and later.left_out == [
        ("2026-11-15", "the hourly ingest has not run since it settled")
    ]
    runs(store, queries_day("2026-11-15"), NOW + DAY)
    assert write(store, path, now=NOW + DAY).days == ["2026-11-15"]


def test_a_clock_stepped_forward_writes_no_empty_days(store, tmp_path):
    path = str(tmp_path / evidence.NAME)
    write(store, path, days=3)
    # the clock jumps 30 days: the ingest ran in none of the days between
    done = write(store, path, now=NOW + 30 * DAY, days=40)
    assert done.days == [d for d in done.days if d <= "2026-11-17"]
    assert all(
        why == "the hourly ingest did not run during it" for d, why in done.left_out if d > "2026-11-17"
    )


def queries_day(day: str) -> float:
    from tvgw import queries

    return queries.day_bounds(day)[0]


def test_the_day_counts_only_its_own_hours_over_the_budget_at_the_ceiling_then(store, lg):
    rng = random.Random(4)
    day = queries_day("2026-11-03")
    synth.insert(store.conn, synth.telemetry_burst(rng, day + 14 * HOUR))
    from tvgw import db

    fixed = {"state": "fixed", "ceiling": 10_000_000, "largest": 1, "since": 0, "until": 1, "days": 14,
             "rule": 2, "measure": "net", "profile": "lg-webos", "tv": None, "set_t": day + 3 * DAY}  # fmt: skip
    db.set_meta(store.conn, "upload_budget", json.dumps(fixed))
    store.conn.commit()
    then = evidence.day_facts(store.conn, lg, "2026-11-03")["uploads_over_budget"]
    assert then["source"] == "floor" and then["ceiling"] == 512 * 1024 and then["over"]
    after = evidence.day_facts(store.conn, lg, "2026-11-07")["uploads_over_budget"]
    assert after["source"] == "fixed" and after["ceiling"] == min(10_000_000, 1_465_000)
    db.set_meta(store.conn, "upload_budget", json.dumps({**fixed, "previous": 700_000}))
    store.conn.commit()
    replaced = evidence.day_facts(store.conn, lg, "2026-11-03")["uploads_over_budget"]
    assert replaced["source"] == "fixed" and replaced["ceiling"] == 700_000
    # a long connection opened on 11-03 and ended on 11-04 is 11-03's hour, never 11-04's too
    store.talk(day + 15 * HOUR, "collector.telemetry.example.com", up_=3_000_000, down_=1_000, seconds=DAY)
    assert evidence.day_facts(store.conn, lg, "2026-11-04")["uploads_over_budget"]["over"] == []


def test_a_broken_chain_is_never_appended_to(store, tmp_path):
    busy_day(store, 16)  # 2026-11-11, the file's third line
    path = str(tmp_path / evidence.NAME)
    write(store, path, days=5)
    lines = lines_of(path)
    lines[2] = lines[2].replace('"refused_lookups":2', '"refused_lookups":0', 1)
    broken = "\n".join(lines) + "\n"
    with open(path, "w", encoding="ascii", newline="") as f:
        f.write(broken)
    with pytest.raises(evidence.BrokenChain) as e:
        write(store, path, now=NOW + 3 * DAY)
    assert e.value.verdict.line == 4 and text_of(path) == broken


# ---- the chain -----------------------------------------------------------------------------------------
@pytest.fixture()
def chain(store, tmp_path):
    for day in range(20):
        busy_day(store, day)
    path = str(tmp_path / evidence.NAME)
    write(store, path, days=6)
    return path, lines_of(path)


def verdict_of(lines: list[str]) -> evidence.Verdict:
    return evidence.check("\n".join(lines) + "\n")


@pytest.mark.parametrize(
    ("change", "line", "problem"),
    [
        (lambda ls: ls[:2] + ls[3:], 3, "its prev is not the SHA-256 of the line above"),  # a day removed
        (lambda ls: [*ls[:3], ls[2], *ls[3:]], 4, "its prev is not the SHA-256 of the line above"),  # repeated
        (lambda ls: [ls[0], ls[2], ls[1], *ls[3:]], 2, "its prev is not the SHA-256 of the line above"),
        (lambda ls: [ls[0], json.dumps(json.loads(ls[1]), indent=1).replace("\n", ""), *ls[2:]], 2,
         "not in the canonical form"),
        (lambda ls: [ls[0], ls[1][:-1], *ls[2:]], 2, "not a JSON line"),
        (lambda ls: ls[1:], 1, "its prev is not the SHA-256 of the line above"),  # the header removed
    ],
)  # fmt: skip
def test_every_kind_of_change_breaks_the_chain_where_it_is(chain, change, line, problem):
    _path, lines = chain
    v = verdict_of(change(lines))
    assert not v.ok and v.line == line and v.problem == problem


def test_changing_any_line_but_the_last_is_caught_and_the_last_changes_the_head(chain):
    """Property: one changed byte in any line before the last breaks the chain; in the last line it
    changes the head, which only a hash written down earlier can show."""
    _path, lines = chain
    head = verdict_of(lines).head
    rng = random.Random(7)
    for i in range(len(lines)):
        for _ in range(6):
            pos = rng.randrange(len(lines[i]))
            ch = lines[i][pos]
            changed = list(lines)
            changed[i] = lines[i][:pos] + ("7" if ch != "7" else "8") + lines[i][pos + 1 :]
            v = verdict_of(changed)
            if i < len(lines) - 1:
                assert not v.ok, (i, pos)
            else:
                assert not v.ok or v.head != head


def test_a_recomputed_chain_or_cut_lines_hold_alone_and_fail_against_a_head_written_down(chain):
    """The chain has no key: a line changed and the chain computed again checks, and so does the file
    with its last lines cut off. Only a head hash kept elsewhere tells."""
    _path, lines = chain
    head = verdict_of(lines).head
    cut = lines[:-2]
    assert verdict_of(cut).ok
    assert not evidence.check("\n".join(cut) + "\n", head=head).ok
    forged, prev = [lines[0]], evidence.digest(lines[0])
    for line in lines[1:]:
        obj = json.loads(line)
        obj["prev"] = prev
        obj["facts"]["record"]["lookups"] += 1
        forged.append(evidence.canonical(obj))
        prev = evidence.digest(forged[-1])
    assert verdict_of(forged).ok
    v = evidence.check("\n".join(forged) + "\n", head=head)
    assert not v.ok and v.problem.startswith("no line has the head hash written down")
    earlier = evidence.digest(lines[3])
    ok = evidence.check("\n".join(lines) + "\n", head=earlier)
    assert ok.ok and ok.head_line == 4


def test_a_byte_that_is_not_ascii_is_refused_never_a_crash(store, chain, tmp_path, monkeypatch, capsys):
    path, lines = chain
    with open(path, "ab") as f:
        f.write(b'{"kind":"day","caf\xc3\xa9":1}\n')
    v = evidence.verify(path)
    assert not v.ok and v.problem == "a byte that is not ASCII" and v.line == len(lines) + 1
    with pytest.raises(evidence.BrokenChain):
        write(store, path, now=NOW + 3 * DAY)
    monkeypatch.setattr(time, "time", lambda: NOW + 3 * DAY)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\nPROFILE=lg-webos\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "--db", store.path, "evidence", "--file", path]) == 1
    assert "a byte that is not ASCII. Nothing was added" in capsys.readouterr().err


def test_a_cut_off_last_line_an_empty_file_a_missing_one_and_a_foreign_version_are_named(chain, tmp_path):
    _path, lines = chain
    assert evidence.check("\n".join(lines)).problem == "its last line is cut off (a write that did not end)"
    assert evidence.check("").problem == "the file is empty"
    assert evidence.verify(str(tmp_path / "none.jsonl")).problem == "there is no evidence file yet"
    head = json.loads(lines[0])
    head["version"] = 2
    v = verdict_of([evidence.canonical(head)])
    assert v.problem == "a version this tvgw does not know" and v.line == 1
    days_out_of_order = json.loads(lines[1])
    days_out_of_order["day"] = "2026-13-40"
    assert verdict_of([lines[0], evidence.canonical(days_out_of_order)]).problem == "not a day line"


def test_the_header_explains_the_file_to_someone_who_never_saw_the_gateway(chain):
    _path, lines = chain
    head = json.loads(lines[0])
    about = " ".join(head["about"])
    for words in ("Observed:", "Estimated:", "refused lookup is an attempt", "no address of the home",
                  "cannot show when a line was written", "The chain has no key", "a file whose last lines"
                  " were cut off still checks", "--verify --head", "no record of which app was in front",
                  "can still be an app's own server", "show how much the TV was used", "a missing day is a"
                  " gap in the record"):  # fmt: skip
        assert words in about
    assert head["format"] == evidence.FORMAT and head["profile"] == "lg-webos"


def test_forget_deletes_the_evidence_directory():
    assert forget.classify(evidence.DIR, forget.STATE_ENTRIES)[0] == forget.FORGET


# ---- the command ---------------------------------------------------------------------------------------
def test_the_command_writes_verifies_and_refuses_a_broken_file(store, tmp_path, monkeypatch, capsys):
    for day in range(20):
        busy_day(store, day)
    monkeypatch.setattr(time, "time", lambda: NOW)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\nPROFILE=lg-webos\n", encoding="utf-8")
    run = ["--conf", str(conf), "--db", store.path, "evidence"]
    assert cli.main([*run, "--days", "3"]) == 0
    out = capsys.readouterr().out
    path = os.path.join(str(tmp_path), "evidence", "evidence.jsonl")
    assert f"added 3 days (2026-11-12 to 2026-11-14) to {path}" in out and "Nothing was sent anywhere" in out
    assert cli.main([*run, "--verify"]) == 0
    assert "the chain holds: 3 days, 2026-11-12 to 2026-11-14" in capsys.readouterr().out
    assert cli.main([*run, "--verify", "--json"]) == 0
    head = json.loads(capsys.readouterr().out)["head"]
    assert cli.main([*run, "--verify", "--head", head]) == 0
    assert "Line 4 has the head hash you gave" in capsys.readouterr().out
    assert cli.main([*run, "--verify", "--head", "0" * 64]) == 1
    assert "no line has the head hash written down" in capsys.readouterr().out
    assert cli.main([*run, "--head", head]) == 2 and cli.main([*run, "--verify", "--head", "abc"]) == 2
    capsys.readouterr()
    with open(path, "a", encoding="ascii") as f:
        f.write('{"kind":"day"}\n')
    assert cli.main([*run, "--verify"]) == 1
    assert "the chain does not hold at line 5" in capsys.readouterr().out
    assert cli.main([*run, "--days", "3"]) == 1
    assert "Nothing was added" in capsys.readouterr().err
    assert cli.main([*run, "--days", "0"]) == 2
