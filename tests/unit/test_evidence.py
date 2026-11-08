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


@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "tvgw.db")
    s.conn.execute("INSERT INTO ingest_runs(t, seconds) VALUES (?, 1)", (H0,))
    s.conn.commit()
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
    assert facts["record"] == {"lookups": 0, "connections": 0, "named_share": None, "tv_readings": 0}


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
                  "does not show when a line was written"):  # fmt: skip
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
    assert json.loads(capsys.readouterr().out)["days"] == 3
    with open(path, "a", encoding="ascii") as f:
        f.write('{"kind":"day"}\n')
    assert cli.main([*run, "--verify"]) == 1
    assert "the chain does not hold at line 5" in capsys.readouterr().out
    assert cli.main([*run, "--days", "3"]) == 1
    assert "Nothing was added" in capsys.readouterr().err
    assert cli.main([*run, "--days", "0"]) == 2
