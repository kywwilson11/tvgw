"""The daily analyst: what leaves the Pi, how the answer is vetted, and the files it writes."""

import json
import os
import re
import socket
import stat
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from tvgw import analyst, cli, db
from tvgw.config import Settings

DAY = "2026-10-26"
A = 1793000000  # inside 2026-10-26 in any US zone? no: fix the day from the timestamp instead


def midday(day):
    from datetime import datetime

    return datetime.strptime(day, "%Y-%m-%d").timestamp() + 12 * 3600


def seeded(tmp_path, s):
    """A store with one day of evidence that carries every identifier the pack must not leak."""
    conn = db.connect(str(tmp_path / "t.db"))
    t = midday(DAY)
    conn.executemany(
        "INSERT INTO dns(t,qname,qtype,answers,blocked,rule) VALUES (?,?,?,?,?,?)",
        [
            (t, "unagi-na.amazon.com", "A", "A:0.0.0.0", 1, "||unagi-na.amazon.com^"),
            (t + 10, "unagi-na.amazon.com", "A", "A:0.0.0.0", 1, "||unagi-na.amazon.com^"),
            (t + 20, "newtracker.example", "A", "A:203.0.113.9", 0, None),
            (t + 30, f"{s.tv_name}.local", "A", "A:10.10.10.17", 0, None),  # the device name as a lookup
            (t + 40, "17.10.10.10.in-addr.arpa", "PTR", "", 0, None),
        ],
    )
    conn.executemany(
        "INSERT INTO hosts(name, category, first_seen, last_seen, dns_n) VALUES (?,?,?,?,?)",
        [("unagi-na.amazon.com", "3rd-party ads", t, t, 2), ("newtracker.example", "Other", t, t, 1)],
    )
    conn.execute(
        "INSERT INTO flows(t_start,t_end,dst,dport,sport,bytes_up,pkts_up,bytes_down) VALUES (?,?,?,443,40000,5000,50,100)",
        (t, t + 60, "203.0.113.9"),
    )
    conn.execute("INSERT INTO lanprobe(t,dst,proto,dport) VALUES (?, '192.168.4.5', 'tcp', 445)", (t,))
    conn.execute(
        "INSERT INTO http(t,host,method,uri,src) VALUES (?, 'plain.example', 'GET', '/track?id=SECRET-QUERY', 'pcap')",
        (t,),
    )
    conn.executemany(
        "INSERT INTO tvstate(t, power, app) VALUES (?,?,?)",
        [
            (t - 3600, "Active", "com.peacock.tv"),
            (t, "Active", "youtube.leanback.v4"),
            (t + 3600, "Standby", ""),
        ],
    )
    conn.execute("INSERT INTO tvsettings(t, key, value) VALUES (?, 'model', 'OLED55CXPUA')", (t,))
    conn.commit()
    conn.close()
    return str(tmp_path / "t.db")


@pytest.fixture
def settings(tmp_path):
    return Settings(
        tv_mac="b4:b2:91:aa:bb:cc",
        tv_name="lgcx",
        tv_ip="10.10.10.17",
        gw_ip="10.10.10.1",
        state_dir=str(tmp_path),
        db_path=seeded(tmp_path, Settings(tv_name="lgcx")),
        reports_dir=str(tmp_path / "reports"),
        auto_rules=str(tmp_path / "auto.rules"),
    )


def test_pack_keeps_the_evidence_and_drops_every_home_identifier(settings, lg):
    import sqlite3

    conn = sqlite3.connect(f"file:{settings.db_path}?mode=ro", uri=True)
    a, b, label, stem = analyst.window(settings, DAY, None)
    assert (label, stem) == (DAY, DAY)
    p = analyst.pack(conn, a, b, label, lg, settings)
    text = json.dumps(p)
    for leak in (
        "b4:b2:91",
        "lgcx",
        "10.10.10.",
        "192.168.",
        "SECRET-QUERY",
        "in-addr.arpa",
        socket.gethostname(),
    ):
        assert leak not in text, leak
    assert "unagi-na.amazon.com" in text and "newtracker.example" in text and "plain.example" in text
    assert p["tv"]["readings_on"] == 2 and p["tv"]["apps_seen"] == ["com.peacock.tv", "youtube.leanback.v4"]
    assert "tvstate" not in p and "lan_probes" not in p and p["lan_probes_dropped"] == 1
    assert all("path" not in h for h in p["plain_http"])
    assert p["profile"]["must_allow"] and p["current_rules"]
    assert any(r.startswith("||*^$dnstype=") for r in p["current_rules"])  # the TV address inside it...
    assert "10.10.10.17" not in text  # ...is scrubbed with everything else


def test_pack_withholds_the_zip_code_and_the_device_name_the_tv_reports(settings, lg):
    """The TV's settings hold where it is and the name someone gave it with the remote, which is not
    TV_NAME: the switches keep their values, those two go as changed, and the scrub learns their
    stored values so they leave nowhere else either, a name the pack is keyed by included."""
    import sqlite3

    t = midday(DAY)
    rw = db.connect(settings.db_path)
    rw.executemany(
        "INSERT INTO tvsettings(t, key, value) VALUES (?,?,?)",
        [
            (t, "option.zipcode", "00000"),
            (t, "network.deviceName", "Den OLED"),
            (t, "option.livePlus", "off"),
        ],
    )
    rw.execute(
        "INSERT INTO dns(t,qname,qtype,answers,blocked) VALUES (?,?,'A','A:203.0.113.7',0)",
        (t, "w-00000.example"),
    )
    rw.execute(
        "INSERT INTO hosts(name, category, first_seen, last_seen, dns_n) VALUES (?,'Other',?,?,1)",
        ("w-00000.example", t, t),
    )
    rw.commit()
    rw.close()
    conn = sqlite3.connect(f"file:{settings.db_path}?mode=ro", uri=True)
    a, b, label, _ = analyst.window(settings, DAY, None)
    p = analyst.pack(conn, a, b, label, lg, settings)
    assert {x["key"]: x["value"] for x in p["tv"]["settings_changes"]} == {
        "model": "OLED55CXPUA",
        "option.livePlus": "off",
        "option.zipcode": analyst.REDACTED,
        "network.deviceName": analyst.REDACTED,
    }
    text = json.dumps(p)
    assert "-00000" not in text and "den oled" not in text.lower(), text
    assert "w-[redacted].example" in p["shapes"]
    assert {"00000", "Den OLED"} <= set(analyst.secrets_for(settings, conn))


def test_scrub_redacts_identifiers_and_caps_sizes():
    secrets = ("b4:b2:91:aa:bb:cc", "lgcx", "kylepi5", "tv")  # "tv" is too short to be a secret
    s = analyst.scrub(
        {
            "a": "TV lgcx at 10.10.10.17 (b4:b2:91:aa:bb:cc) via kylepi5 to 203.0.113.9 and 1.1.1.1",
            "b": "lgtvsdp.com stays; LGCX too; esc\x1b[2Jape",
            "c": list(range(60)),
            "d": "x" * 500,
            "n": 7,
        },
        secrets,
    )
    assert s["a"] == "TV [redacted] at [redacted] ([redacted]) via [redacted] to 203.0.113.9 and 1.1.1.1"
    assert s["b"] == "lgtvsdp.com stays; [redacted] too; esc [2Jape"
    assert len(s["c"]) == 41 and s["c"][-1] == "... 20 more left out" and s["n"] == 7
    assert len(s["d"]) == 200 and s["d"].endswith("…")
    assert (
        analyst.scrub("multicast 224.0.0.1 loop 127.0.0.1 link 169.254.1.1")
        == "multicast [redacted] loop [redacted] link [redacted]"
    )


def test_vet_judges_rules_like_the_profile_lint(lg):
    current = lg.adguard_rules("10.10.10.1", "10.10.10.17")
    result = {
        "summary": "A day.",
        "nothing_to_do": False,
        "proposals": [
            {
                "kind": "block",
                "name": "tracker.example",
                "rule": "||tracker.example^",
                "reason": "telemetry",
                "evidence": ["new_hosts: tracker.example"],
                "risk": "low",
                "rollback": "remove the rule",
            },
            {
                "kind": "block",
                "name": "us.lgtvsdp.com",
                "rule": "||us.lgtvsdp.com^",
                "reason": "?",
                "evidence": [],
                "risk": "high",
                "rollback": "",
            },
            {
                "kind": "block",
                "name": "lgtvsdp.com",
                "rule": "||lgtvsdp.com^",
                "reason": "apex",
                "evidence": [],
                "risk": "high",
                "rollback": "",
            },
            {
                "kind": "block",
                "name": "dup",
                "rule": current[-1],
                "reason": "already there",
                "evidence": [],
                "risk": "low",
                "rollback": "",
            },
            {
                "kind": "allow",
                "name": "x.example",
                "rule": "||x.example^",
                "reason": "wrong shape",
                "evidence": [],
                "risk": "low",
                "rollback": "",
            },
            {
                "kind": "block",
                "name": "weird",
                "rule": "block example.com please",
                "reason": "prose",
                "evidence": [],
                "risk": "low",
                "rollback": "",
            },
            {
                "kind": "unblock",
                "name": "gone",
                "rule": "||never-was.example^",
                "reason": "",
                "evidence": [],
                "risk": "low",
                "rollback": "",
            },
            {
                "kind": "unblock",
                "name": "real",
                "rule": current[-1],
                "reason": "breakage",
                "evidence": [],
                "risk": "medium",
                "rollback": "re-add",
            },
            {
                "kind": "watch",
                "name": "new.example",
                "rule": "",
                "reason": "unclear",
                "evidence": [],
                "risk": "low",
                "rollback": "none",
            },
            {
                "kind": "block",
                "name": "regex",
                "rule": "/^ads[0-9]+\\.example$/",
                "reason": "pattern",
                "evidence": [],
                "risk": "low",
                "rollback": "",
            },
            {
                "kind": "block",
                "name": "no rule",
                "rule": "",
                "reason": "",
                "evidence": [],
                "risk": "low",
                "rollback": "",
            },
            {
                "kind": "nonsense",
                "name": "odd",
                "rule": "",
                "reason": "",
                "evidence": [],
                "risk": "weird",
                "rollback": "",
            },
            {
                "kind": "block",
                "name": "thirteenth",
                "rule": "||more.example^",
                "reason": "",
                "evidence": [],
                "risk": "low",
                "rollback": "",
            },
        ],
    }
    v = analyst.vet(result, lg, current)
    verdicts = [p["vetted"] for p in v["proposals"]]
    assert len(v["proposals"]) == 12  # the thirteenth is dropped: MAX_PROPOSALS
    assert verdicts[0] == "ok"
    assert verdicts[1].startswith("refused: block rule 'us.lgtvsdp.com' covers must-allow")
    assert verdicts[2].startswith("refused: block rule 'lgtvsdp.com'")  # the lint speaks first
    assert verdicts[3] == "refused: already in place"
    assert verdicts[4] == "refused: an allow rule starts with @@"
    assert verdicts[5] == "refused: not one AdGuard DNS rule"
    assert verdicts[6] == "refused: no such rule in place" and verdicts[7] == "ok"
    assert verdicts[8] == "ok" and verdicts[9] == "ok" and verdicts[10] == "refused: no rule"
    assert v["proposals"][11]["kind"] == "question" and v["proposals"][11]["risk"] == "high"
    assert v["vetted_ok"] == 5


def test_vet_refuses_modifiers_that_bend_or_remove_policy(lg):
    """A heading says block or allow; the modifier decides what the rule does. `$badfilter` disables
    the rule it names (the clock host's exception, or a block), `$dnsrewrite` sends the TV to an
    address, `$client` and the like change whom it is for, and a `$dnstype` over every name skips the
    lint's host checks. Only `$important`, and on a block `$dnstype` with the strippable types for
    one named host, pass."""
    current = lg.adguard_rules("10.10.10.1", "10.10.10.17")

    def verdict(kind, rule):
        result = {"proposals": [{"kind": kind, "name": "x", "rule": rule, "risk": "low"}]}
        return analyst.vet(result, lg, current)["proposals"][0]["vetted"]

    assert verdict("allow", "@@||us.lgtvsdp.com^$important,badfilter") == (
        "refused: $badfilter is not for proposals"
    )
    assert verdict("block", "||doubleclick.net^$badfilter") == "refused: $badfilter is not for proposals"
    assert verdict("block", "||api.amazonvideo.com^$dnsrewrite=203.0.113.66") == (
        "refused: $dnsrewrite is not for proposals"
    )
    assert (
        verdict("block", "||tracker.example^$client=10.10.10.17") == "refused: $client is not for proposals"
    )
    assert verdict("block", "||tracker.example^$important=1") == "refused: $important=1 is not for proposals"
    assert verdict("allow", "@@||cdn.example^$dnstype=https") == "refused: $dnstype is not for proposals"
    assert verdict("block", "||*^$dnstype=a") == "refused: $dnstype names one host, not every name"
    assert verdict("block", "||*.*^$dnstype=https") == "refused: $dnstype names one host, not every name"
    for bad in (
        "||tracker.example^$dnstype=a",
        "||tracker.example^$dnstype=~a",
        "||tracker.example^$dnstype",
    ):
        assert verdict("block", bad) == "refused: $dnstype may only withhold HTTPS or SVCB", bad
    for kind, good in (
        ("block", "||tracker.example^"),
        ("block", "||tracker.example^$important"),
        ("block", "||tracker.example^$dnstype=https|svcb"),
        ("allow", "@@||cdn.example^$important"),
        ("allow", "@@||cdn.example^"),
        ("block", "/^ads[0-9]+\\.example$/"),
    ):
        assert verdict(kind, good) == "ok", good


def test_every_rule_form_the_prompt_names_vets_ok(lg):
    """The prompt teaches the rule forms; a proposal that follows it exactly must not be refused as
    "not one AdGuard DNS rule". Record types are written back upper-case, as the profile writes them."""
    forms = re.findall(r"`([^`]*\bhost\b[^`]*)`", analyst.SYSTEM)
    assert "||host^$dnstype=HTTPS|SVCB" in forms and len(forms) == 3, forms
    for form in forms:
        rule = form.replace("host", "fresh.example")
        kind = "allow" if rule.startswith("@@") else "block"
        result = {"proposals": [{"kind": kind, "name": "fresh.example", "rule": rule, "risk": "low"}]}
        (p,) = analyst.vet(result, lg, lg.adguard_rules())["proposals"]
        assert (p["vetted"], p["rule"]) == ("ok", rule), form
    lower = {"proposals": [{"kind": "block", "name": "x", "rule": "||x.example^$dnstype=https|Svcb"}]}
    (p,) = analyst.vet(lower, lg, ["||x.example^$dnstype=HTTPS|SVCB"])["proposals"]
    assert (p["rule"], p["vetted"]) == ("||x.example^$dnstype=HTTPS|SVCB", "refused: already in place")


class FakeStream:
    def __init__(self, msg):
        self.msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get_final_message(self):
        return self.msg


class FakeClient:
    def __init__(self, msg):
        self.msg, self.calls = msg, []
        self.messages = SimpleNamespace(stream=self._stream)

    @contextmanager
    def _stream(self, **kw):
        self.calls.append(kw)
        yield FakeStream(self.msg)


def message(text, stop="end_turn", category=None):
    return SimpleNamespace(
        stop_reason=stop,
        stop_details=SimpleNamespace(category=category) if category else None,
        content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(input_tokens=12000, output_tokens=900, cache_read_input_tokens=0),
    )


def test_call_sends_the_schema_and_reads_the_answer_or_the_refusal():
    answer = {"summary": "quiet", "nothing_to_do": True, "proposals": []}
    client = FakeClient(message(json.dumps(answer)))
    result, usage = analyst.call(client, "sys", "user")
    assert result == answer and usage["input_tokens"] == 12000
    (kw,) = client.calls
    assert kw["model"] == analyst.MODEL and kw["output_config"]["format"]["schema"] is analyst.SCHEMA
    assert kw["output_config"]["effort"] == "high" and "thinking" not in kw and "temperature" not in kw
    assert kw["messages"] == [{"role": "user", "content": "user"}] and kw["system"][0]["text"] == "sys"
    refused, _ = analyst.call(FakeClient(message("", stop="refusal", category="cyber")), "s", "u")
    assert refused == {"refused": "cyber"}
    with pytest.raises(RuntimeError, match="cut off"):
        analyst.call(FakeClient(message("{", stop="max_tokens")), "s", "u")


def test_a_cut_off_answer_has_room_and_its_spend_is_recorded(settings, lg, tmp_path, capsys):
    """Thinking counts toward max_tokens, so a deep pass needs the streaming default's room; and an
    answer cut off anyway was billed, so the record says what it cost and that nothing came of it."""
    key = tmp_path / "k"
    key.write_text("sk-ant-test\n")
    key.chmod(0o600)
    client = FakeClient(message("{", stop="max_tokens"))
    assert analyst.run(settings, lg, DAY, make_client=lambda k: client, key_path=str(key), force=True) == 1
    assert client.calls[0]["max_tokens"] == analyst.MAX_TOKENS >= 64000
    assert "cut off" in capsys.readouterr().out
    record = json.loads((tmp_path / "reports" / "proposals" / f"{DAY}.json").read_text())
    assert record["cut_off"] and record["proposals"] == [] and record["usage"]["output_tokens"] == 900
    assert record["cost_usd"] == round((12000 * 4 + 900 * 20) / 1e6, 4)
    md = (tmp_path / "reports" / "proposals" / f"{DAY}.md").read_text()
    assert "cut off" in md and "Tokens in 12000, out 900" in md


def test_run_dry_run_sends_nothing_and_writes_what_would_leave(settings, lg, tmp_path, capsys):
    rc = analyst.run(settings, lg, DAY, dry_run=True, make_client=lambda k: pytest.fail("called"))
    assert rc == 0
    d = analyst.proposals_dir(settings)
    pack_text = (tmp_path / "reports" / "proposals" / f"{DAY}.pack.json").read_text()
    assert "lgcx" not in pack_text and "b4:b2:91" not in pack_text and "newtracker.example" in pack_text
    prompt = (tmp_path / "reports" / "proposals" / f"{DAY}.prompt.txt").read_text()
    assert prompt.startswith(analyst.SYSTEM) and "Evidence pack for 2026-10-26" in prompt
    assert "nothing sent" in capsys.readouterr().out
    assert oct(stat.S_IMODE(os.stat(os.path.join(d, f"{DAY}.pack.json")).st_mode)) == "0o640"


def test_run_without_a_key_says_so_and_refuses_a_loose_key(settings, lg, tmp_path, capsys):
    assert analyst.run(settings, lg, DAY, key_path=str(tmp_path / "none")) == 0
    assert "no key" in capsys.readouterr().out
    loose = tmp_path / "loose.key"
    loose.write_text("sk-ant-test\n")
    loose.chmod(0o644)
    with pytest.raises(PermissionError, match="readable by others"):
        analyst.read_key(str(loose))
    loose.chmod(0o600)
    assert analyst.read_key(str(loose)) == "sk-ant-test"


def test_pack_and_vet_see_every_rule_in_place(settings, lg, tmp_path):
    """The model is told never to re-propose a rule in place and the vet refuses one, so both need the
    whole list, past the pack's list cap, the machine's own rules (design decision 20) included."""
    from tvgw import autoblock

    autoblock.add_rule(settings.auto_rules, "||machine.example^", "test")
    rules = lg.adguard_rules(settings.gw_ip, settings.tv_ip)
    assert len(rules) > analyst.LIST_CAP + 1
    hidden = rules[-1]  # past the cap
    answer = {
        "summary": "repeats",
        "nothing_to_do": False,
        "proposals": [
            {"kind": "block", "name": "a", "rule": hidden, "reason": "", "evidence": [], "risk": "low",
             "rollback": ""},
            {"kind": "unblock", "name": "b", "rule": hidden, "reason": "", "evidence": [], "risk": "low",
             "rollback": ""},
            {"kind": "block", "name": "machine.example", "rule": "||machine.example^", "reason": "",
             "evidence": [], "risk": "low", "rollback": ""},
        ],
    }  # fmt: skip
    key = tmp_path / "k"
    key.write_text("sk-ant-test\n")
    key.chmod(0o600)
    client = FakeClient(message(json.dumps(answer)))
    assert analyst.run(settings, lg, DAY, make_client=lambda k: client, key_path=str(key), force=True) == 0
    sent = json.loads(client.calls[0]["messages"][0]["content"].split("\n", 1)[1])
    assert len(sent["current_rules"]) == len(rules) + 1
    assert hidden in sent["current_rules"] and "||machine.example^" in sent["current_rules"]
    assert not any("more left out" in r for r in sent["current_rules"])
    record = json.loads((tmp_path / "reports" / "proposals" / f"{DAY}.json").read_text())
    assert [x["vetted"] for x in record["proposals"]] == [
        "refused: already in place",
        "ok",
        "refused: already in place",
    ]


def test_run_with_a_key_writes_vetted_proposals(settings, lg, tmp_path, capsys):
    key = tmp_path / "k"
    key.write_text("sk-ant-test\n")
    key.chmod(0o600)
    answer = {
        "summary": "One new tracker.",
        "nothing_to_do": False,
        "proposals": [
            {
                "kind": "block",
                "name": "newtracker.example",
                "rule": "||newtracker.example^",
                "reason": "telemetry cadence",
                "evidence": ["new_hosts: newtracker.example"],
                "risk": "low",
                "rollback": "delete the line",
            },
            {
                "kind": "block",
                "name": "us.lgtvsdp.com",
                "rule": "||us.lgtvsdp.com^",
                "reason": "bad idea",
                "evidence": [],
                "risk": "high",
                "rollback": "",
            },
        ],
    }
    seen = {}

    def make_client(k):
        seen["key"] = k
        return FakeClient(message(json.dumps(answer)))

    assert analyst.run(settings, lg, DAY, make_client=make_client, key_path=str(key)) == 0
    assert seen["key"] == "sk-ant-test"
    out = capsys.readouterr().out
    assert "2 proposal(s), 1 vetted ok" in out
    md = (tmp_path / "reports" / "proposals" / f"{DAY}.md").read_text()
    assert "## 1. block: newtracker.example" in md and "Vetted: ok" in md
    assert "refused: block rule 'us.lgtvsdp.com' covers must-allow" in md and "Nothing here is applied" in md
    record = json.loads((tmp_path / "reports" / "proposals" / f"{DAY}.json").read_text())
    assert (
        record["model"] == analyst.MODEL
        and record["usage"]["output_tokens"] == 900
        and record["vetted_ok"] == 1
    )
    assert record["cost_usd"] == round((12000 * 4 + 900 * 20) / 1e6, 4) and record["effort"] == "high"
    assert analyst.latest(settings).endswith(f"{DAY}.md")


def test_show_picks_the_newest_file_written_not_the_last_name(settings):
    """`YYYY-Www` sorts after every `YYYY-MM-DD` of its year ('W' after the digits), so by name the
    first weekly file would be "the newest" until January."""
    d = analyst.proposals_dir(settings)
    os.makedirs(d)
    for i, name in enumerate(
        ("2026-W44.md", "2026-11-02.md", "2026-11-03.claude-fable-5-1.md", "2026-11-04.md")
    ):
        path = os.path.join(d, name)
        with open(path, "w") as fh:
            fh.write(name)
        os.utime(path, (1793000000 + i * 3600, 1793000000 + i * 3600))
    assert analyst.latest(settings) == os.path.join(d, "2026-11-04.md")
    os.utime(os.path.join(d, "2026-W44.md"), (1793100000, 1793100000))  # the weekly pass ran after
    assert analyst.latest(settings) == os.path.join(d, "2026-W44.md")


def test_cli_analyst_show_and_dry_run(settings, lg, tmp_path, capsys, monkeypatch):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(
        f"TV_MAC={settings.tv_mac}\nTV_NAME={settings.tv_name}\nSTATE_DIR={settings.state_dir}\n"
        f"DB_PATH={settings.db_path}\nREPORTS_DIR={settings.reports_dir}\n"
        f"AUTO_RULES={settings.auto_rules}\n"
    )
    assert cli.main(["--conf", str(conf), "analyst", "--show"]) == 1
    assert "no proposals yet" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf), "analyst", "--dry-run", "--day", DAY]) == 0
    assert "nothing sent" in capsys.readouterr().out


def test_model_and_effort_come_from_the_settings(settings, lg, tmp_path, capsys):
    from dataclasses import replace

    key = tmp_path / "k"
    key.write_text("sk-ant-test\n")
    key.chmod(0o600)
    answer = {"summary": "quiet", "nothing_to_do": True, "proposals": []}
    client = FakeClient(message(json.dumps(answer)))
    s2 = replace(settings, analyst_model="claude-sonnet-5-5", analyst_effort="medium")
    assert analyst.run(s2, lg, DAY, make_client=lambda k: client, key_path=str(key)) == 0
    (kw,) = client.calls
    assert kw["model"] == "claude-sonnet-5-5" and kw["output_config"]["effort"] == "medium"
    out = capsys.readouterr().out
    assert "$0.03 (claude-sonnet-5-5, effort medium)" in out  # 12000*2 + 900*10 per million
    record = json.loads((tmp_path / "reports" / "proposals" / f"{DAY}.json").read_text())
    assert record["model"] == "claude-sonnet-5-5" and record["cost_usd"] == round(
        (12000 * 2 + 900 * 10) / 1e6, 4
    )
    assert analyst.cost({"input_tokens": 1000, "output_tokens": 0}, "some-new-model") is None


def test_settings_validate_the_analyst_knobs(tmp_path):
    from tvgw import config

    conf = tmp_path / "tvgw.conf"
    conf.write_text("ANALYST_MODEL=claude-sonnet-5-5\nANALYST_EFFORT=xhigh\n")
    s = config.load(str(conf))
    assert (s.analyst_model, s.analyst_effort) == ("claude-sonnet-5-5", "xhigh")
    conf.write_text("ANALYST_EFFORT=turbo\n")
    with pytest.raises(ValueError, match="ANALYST_EFFORT"):
        config.load(str(conf))
    conf.write_text("ANALYST_MODEL=not a model\n")
    with pytest.raises(ValueError, match="ANALYST_MODEL"):
        config.load(str(conf))


def test_window_follows_the_flags_then_the_conf(settings):
    from dataclasses import replace

    now = midday("2026-10-28")
    a, b, label, stem = analyst.window(settings, None, 6, now=now)
    assert (b - a, label, stem) == (6 * 3600, "the 6 h to 2026-10-28 12:00", "2026-10-28T1200-6h")
    a, b, label, stem = analyst.window(replace(settings, analyst_window="3h"), None, None, now=now)
    assert b - a == 3 * 3600 and stem.endswith("-3h")
    a, b, label, stem = analyst.window(settings, None, None, now=now)
    assert stem == label and len(label) == 10  # yesterday, as a date


def test_cli_flags_override_the_conf_and_name_the_comparison_file(
    settings, lg, tmp_path, capsys, monkeypatch
):
    key = tmp_path / "k"
    key.write_text("sk-ant-test\n")
    key.chmod(0o600)
    monkeypatch.setattr(analyst, "KEY_PATH", str(key))
    answer = {"summary": "quiet", "nothing_to_do": True, "proposals": []}
    client = FakeClient(message(json.dumps(answer)))
    real = pytest.importorskip("anthropic")
    monkeypatch.setattr(real, "Anthropic", lambda **kw: client)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(
        f"TV_MAC={settings.tv_mac}\nTV_NAME={settings.tv_name}\nSTATE_DIR={settings.state_dir}\n"
        f"DB_PATH={settings.db_path}\nREPORTS_DIR={settings.reports_dir}\n"
        f"AUTO_RULES={settings.auto_rules}\n"
    )
    rc = cli.main(
        ["--conf", str(conf), "analyst", "--day", DAY, "--model", "claude-fable-5-1", "--effort", "max"]
    )
    assert rc == 0
    (kw,) = client.calls
    assert kw["model"] == "claude-fable-5-1" and kw["output_config"]["effort"] == "max"
    assert (tmp_path / "reports" / "proposals" / f"{DAY}.claude-fable-5-1.md").exists()
    assert "(claude-fable-5-1, effort max)" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf), "analyst", "--since", "6h", "--day", DAY]) == 2
    assert cli.main(["--conf", str(conf), "analyst", "--since", "soon"]) == 2
    assert cli.main(["--conf", str(conf), "analyst", "--since", "6h", "--dry-run"]) == 0
    assert any(f.name.endswith("-6h.pack.json") for f in (tmp_path / "reports" / "proposals").iterdir())


def test_window_and_schedule_settings_are_checked(tmp_path):
    from tvgw import config

    conf = tmp_path / "tvgw.conf"
    for text, ok in (
        ("ANALYST_WINDOW=6h\nANALYST_SCHEDULE=hourly\n", True),
        ("ANALYST_WINDOW=day\nANALYST_SCHEDULE=*-*-* 06,18:00:00\n", True),
        ("ANALYST_WINDOW=0h\n", False),
        ("ANALYST_WINDOW=200h\n", False),
        ("ANALYST_WINDOW=soon\n", False),
        ("ANALYST_SCHEDULE=hourly; rm -rf /\n", False),
    ):
        conf.write_text(text)
        if ok:
            config.load(str(conf))
        else:
            with pytest.raises(ValueError, match="ANALYST_"):
                config.load(str(conf))


def test_weekly_pass_uses_its_own_model_window_and_switch(settings, lg, tmp_path, capsys):
    from dataclasses import replace

    key = tmp_path / "k"
    key.write_text("sk-ant-test\n")
    key.chmod(0o600)
    answer = {"summary": "a week", "nothing_to_do": True, "proposals": []}
    client = FakeClient(message(json.dumps(answer)))
    assert (
        analyst.run(settings, lg, weekly=True, make_client=lambda k: client, key_path=str(key), force=True)
        == 0
    )
    (kw,) = client.calls
    assert kw["model"] == "claude-fable-5-1" and kw["output_config"]["effort"] == "high"
    files = sorted(f.name for f in (tmp_path / "reports" / "proposals").iterdir())
    assert any(re.fullmatch(r"\d{4}-W\d{2}\.md", f) for f in files), files
    record = json.loads(next((tmp_path / "reports" / "proposals").glob("*-W*.json")).read_text())
    assert record["window"].startswith("ISO week ") and record["until"] - record["since"] == 7 * 86400
    off = replace(settings, analyst_weekly_model="off")
    assert (
        analyst.run(off, lg, weekly=True, make_client=lambda k: pytest.fail("called"), key_path=str(key)) == 0
    )
    assert "weekly pass is off" in capsys.readouterr().out
    a, b, label, stem = analyst.window(settings, None, None, week="2026-W43")
    assert (label, stem, b - a) == ("ISO week 2026-W43", "2026-W43", 7 * 86400)
    assert analyst.last_week(midday("2026-10-28")) == "2026-W43"


def test_apply_mode_and_verifier_settings_are_checked(tmp_path):
    from tvgw import config

    conf = tmp_path / "tvgw.conf"
    conf.write_text(
        "ANALYST_APPLY=auto\nANALYST_VERIFIER_MODEL=claude-opus-5-5\nANALYST_VERIFIER_EFFORT=max\n"
    )
    s = config.load(str(conf))
    assert (s.analyst_apply, s.analyst_verifier_model, s.analyst_verifier_effort) == (
        "auto",
        "claude-opus-5-5",
        "max",
    )
    for bad in (
        "ANALYST_APPLY=yes\n",
        "ANALYST_VERIFIER_MODEL=no model\n",
        "ANALYST_VERIFIER_EFFORT=turbo\n",
    ):
        conf.write_text(bad)
        with pytest.raises(ValueError, match="ANALYST_"):
            config.load(str(conf))
