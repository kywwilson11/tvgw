"""(plain) The plain brief (design decision 58): its golden lines, the tiers, every red line's row, the
menu paths from the profile, the first-day line, and BRIEF_STYLE, absent of which `tvgw brief`, `tvgw
report --day` and the daily files are what they were."""

import ast
import inspect
import io
import json
import re
import shutil
import subprocess
import sys
import textwrap

import pytest
from conftest import NOW, ROOT
from test_cli_rich import EVERY_SECTION, full_brief

from tvgw import cli, db, ledger, plain, profile, queries

DAY = 86400


# ---- the golden lines ---------------------------------------------------------------------------------
def measured_day() -> dict:
    """The day of design section 2.5: the LG CX's measured lookups in the four tracking categories
    (docs/tv/lg-cx-measured.md), every check passed, five hourly readings with the TV on."""
    since, until = queries.day_bounds("2026-11-04")
    cats = [
        ("LG ads", 29, 29),
        ("LG telemetry", 155, 155),
        ("LG fingerprint", 1056, 1056),
        ("LG core", 300, 0),
        ("3rd-party ads", 2743, 2743),
        ("Streaming", 266, 0),
        ("Other", 46, 46),
    ]
    return {
        "day": "2026-11-04",
        "since": since,
        "until": until,
        "generated": until + 10 * 3600,  # read the morning after
        "coverage": {"not_assessed": [], "warnings": [], "sources": {}},
        "dns": {"lookups": 4595, "blocked": 4029, "names": 300},
        "categories": [{"category": c, "lookups": n, "blocked": b} for c, n, b in cats],
        "firewall": {"runs": 144, "failed": 0, "expected": 144},
        "tvstate": [{"time": f"{h}:20", "power": "Active", "app": "netflix"} for h in range(18, 23)]
        + [{"time": "23:20", "power": "Active Standby", "app": ""}],
        "new_hosts": [{"name": "rr3---sn-x.googlevideo.com", "category": "Streaming", "new_domain": 0}],
        "firmware_changes": [],
        "list_changes": {"newly_blocked": [], "newly_allowed": []},
        "red_lines": [],
    }


def test_the_measured_day_reads_as_the_design_shows_it(lg):
    """Design section 2.5, line for line (the hours and the check count are its illustration)."""
    o = measured_day()
    assert plain.plain_brief(o, plain.activity_from_readings(o), None, profile=lg) == [
        "tvgw brief, Wednesday 4 November (yesterday, 24 hours)",
        "  Protection: held all day (144 of 144 checks passed).",
        "  The TV: on about 5 hours. It asked for known tracking services 3,983 times; every one was refused.",
        "  Blocked most: other advertisers, device fingerprinting, LG usage reporting.",
        "  New: nothing new.",
        "  Action: nothing needs your attention.",
        "Engineering report: tvgw brief --full",
    ]


def test_the_golden_plain_brief_of_the_rich_fixture(lg):
    """The brief with every section populated, in plain words: a transient and an unknown red line are
    the doctor tier, a source not read makes the record incomplete, CDN churn is not news."""
    o = full_brief()
    assert plain.plain_brief(o, plain.activity_from_readings(o), None, profile=lg) == [
        "tvgw brief, Monday 26 October 2026 (24 hours)",
        "  Protection: held most of the day (1 of 24 checks failed). Part of the day's record is missing.",
        "  The TV: on about 1 hour. It asked for no known tracking service by name.",
        "  Blocked most: nothing was blocked.",
        "  New: the TV's software updated to 04.65.20; the TV used 1 new service (a.example); a blocklist"
        " update now blocks media.example, which the TV downloaded from.",
        f"  Action: Something the TV needs in order to work was blocked. {plain.doctor_action()} 2 more things"
        " need a look: tvgw brief --full.",
        # (tripwire) the fixture's While off/asleep line has traffic, and no names
        "  While off: Between two hourly checks that found it switched off, the TV went online: 3 lookups and"
        " 1 connection. Either it was switched on in between, or it goes online while it is off.",
        "Engineering report: tvgw brief --full",
    ]


def test_a_clean_day_needs_nothing(lg):
    o = measured_day()
    assert plain.action(o, lg) is None
    assert plain.plain_brief(o, profile=lg)[5] == "  Action: nothing needs your attention."


def test_live_plus_on_is_the_act_tier_with_the_profiles_menu_path(lg):
    o = {**measured_day(), "red_lines": ["Live Plus (ACR) is on on the TV (since 2026-11-04 20:00): x"]}
    assert plain.action(o, lg) == (
        "act",
        "Live Plus (LG's viewing-data collection) is on. On the TV: Settings > General > Additional"
        " Settings > Live Plus: off.",
    )


def test_the_act_tier_comes_before_the_doctor_tier_and_detail_is_left_out(lg):
    reds = [
        "ingest warnings: 2",
        "firewall checks failed 1 of 144 times; last: FAIL x",
        "Encrypted ClientHello in 3 handshakes since x",
        "TV has a second network path: Wi-Fi is connected (since x): y",
        "TV has a second network path: Wi-Fi Direct is on (since x): y",
    ]
    o = {**measured_day(), "red_lines": reds}
    assert plain.items(o, lg) == [
        (
            "act",
            "The TV's Wi-Fi, or another of its radios, is on, so it can reach the internet around the gateway.",
            "On the TV: switch Wi-Fi off, forget every saved network, and switch off Wi-Fi Direct and any"
            " tethering.",
        ),
        ("doctor", "The gateway's self-check failed at least once.", plain.doctor_action()),
    ]
    assert plain.action(o, lg)[1].endswith("1 more thing needs a look: tvgw brief --full.")
    only_detail = {**measured_day(), "red_lines": ["ingest warnings: 2", "machine rule ||x^ has spent"]}
    assert plain.action(only_detail, lg) is None  # (D14) transients and engineering stay in --full


def test_an_unknown_red_line_is_the_doctor_tier_never_detail():
    assert plain.tier("a red line written after this table")[0] == "doctor" == plain.UNKNOWN_TIER


def test_a_consent_flip_says_how_it_happens_and_asks_only_to_decline(lg):
    """The red line's own words: an agreement is accepted at the remote or by a software update, so the
    plain sentence blames no one, and its action declines; it never suggests accepting anything."""
    o = {**measured_day(), "red_lines": ["TV consent flag acrAllowed turned on (at 20:00): an agreement x"]}
    t, text = plain.action(o, lg)
    assert t == "act" and text == (
        "One of the TV's data agreements was accepted, at the remote or by a software update. On the TV:"
        " open its privacy or user-agreement settings and decline it again (tvgw brief --full names it)."
    )
    for *_, act in plain.RED_LINE_PLAIN:
        assert "accept" not in act.replace("user-agreement", ""), act  # no action asks to accept


def test_the_second_paths_fix_is_verifys_fix_word_for_word():
    """The reader meets a second network path in the brief and in `tvgw verify`'s plain words: both give
    the same steps at the TV, so a change to one is a change to the other."""
    from tvgw import verify

    (row,) = [r for r in plain.RED_LINE_PLAIN if r[0] == "TV has a second network path:"]
    steps = row[3].removeprefix("On the TV: ")
    assert f"On the TV, {steps}" in verify.PLAIN["tv_paths"][2]


def test_the_gateways_trouble_names_tvgw_doctor_only_once_this_version_has_it(monkeypatch):
    """Until `tvgw doctor` exists the plain brief sends the reader to `tvgw verify`, whose FAIL lines say
    what is wrong; with it, to the doctor (design section 2.5)."""
    real = cli.build_parser

    def parser(doctor: bool):
        p = real()
        sub = next(a for a in p._actions if a.__class__.__name__ == "_SubParsersAction")
        if not doctor:
            sub.choices.pop("doctor", None)
        elif "doctor" not in sub.choices:
            sub.add_parser("doctor")
        return p

    try:
        for doctor, said in ((False, "Run sudo tvgw verify."), (True, "Run sudo tvgw doctor.")):
            plain.doctor_action.cache_clear()
            monkeypatch.setattr(cli, "build_parser", lambda doctor=doctor: parser(doctor))
            assert plain.doctor_action() == said
    finally:
        plain.doctor_action.cache_clear()


COMMAND = re.compile(r"\btvgw ([a-z][a-z-]*(?: --?[a-z-]+)*)")


def test_every_command_the_plain_brief_names_exists_in_this_version(lg):
    """Each `tvgw ...` in a row, an action as the reader gets it, or a fixed line parses with tvgw's own
    parser, the rule verify's plain texts follow."""
    texts = [s for row in plain.RED_LINE_PLAIN for s in row[2:]]
    texts += [plain.action_text(row[3], lg) for row in plain.RED_LINE_PLAIN]
    texts += [plain.FOOTER, plain.GENERIC_SETTING, plain.MISSING_RECORD[1], plain.doctor_action()]
    found = {m for text in texts for m in COMMAND.findall(text)}
    assert "brief --full" in found and any(c in found for c in ("doctor", "verify"))
    parser = cli.build_parser()
    for command in sorted(found):
        parser.parse_args(command.split())  # SystemExit on a subcommand or a flag tvgw does not have


def test_hours_estimated_from_traffic_say_so_and_no_reading_says_nothing():
    o = measured_day()
    line = plain.plain_brief(o, plain.Activity(3.4, estimated=True))[2]
    assert line.startswith("  The TV: on about 3 hours (estimated from its traffic). It asked")
    assert plain.plain_brief(o, None)[2].startswith("  The TV: asked for known tracking services 3,983")
    unknown = {**o, "tvstate": [{"time": "09:20", "power": "unknown", "app": ""}]}
    assert plain.activity_from_readings(unknown) is None  # nothing was asked: not "off"
    off = {**o, "tvstate": [{"time": "09:20", "power": "unreachable", "app": ""}]}
    assert plain.plain_brief(off, plain.activity_from_readings(off))[2].startswith(
        "  The TV: off at every hourly check. It asked"
    )


def test_hours_on_count_clock_hours_not_readings():
    """A deploy or a reading by hand adds readings between the hourly ones: three readings in the 18:00
    hour that say the TV was on are one hour, and a reading that says off adds none."""
    readings = [("18:20", "Active"), ("18:41", "Active"), ("18:52", "Screen Saver"), ("19:20", "Active")]
    readings += [("20:20", "Active Standby"), ("20:44", "unreachable")]
    o = {**measured_day(), "tvstate": [{"time": t, "power": p, "app": ""} for t, p in readings]}
    assert plain.activity_from_readings(o) == plain.Activity(hours=2.0)
    assert plain.plain_brief(o, plain.activity_from_readings(o))[2].startswith("  The TV: on about 2 hours.")
    # a window over a day formats its times with the date: the same clock hour of two days is two hours
    week = {**o, "tvstate": [{"time": f"11-0{d} 18:20", "power": "Active", "app": ""} for d in (3, 4)]}
    assert plain.activity_from_readings(week) == plain.Activity(hours=2.0)


def test_tracking_lookups_that_were_answered_are_counted_apart():
    o = measured_day()
    o["categories"] = [{"category": "3rd-party ads", "lookups": 10, "blocked": 7}]
    assert plain.plain_brief(o)[2] == (
        "  The TV: asked for known tracking services 10 times; 7 were refused and 3 answered"
        " (tvgw brief --full lists them)."
    )


# words that would tell the reader no tracking happened, which the wire cannot show: ads a server stitches
# into the stream, an app's own logging and matching by the home's address never reach the gateway
# (docs/what-it-stops.md#what-it-cannot-stop, research pass 4)
ABSENCE = re.compile(
    r"\bno (?:ad |known )?(?:tracking|trackers?|ads?|advertising)\b(?! service by name)"
    r"|\btracking[- ]free\b|\bnot tracked\b|\bnothing (?:was )?tracked\b|\bno one tracked\b"
    r"|\b(?:all|every) (?:tracking|tracker)s? (?:was |were )?(?:stopped|blocked)\b"
    # what the TV did with its clock, which the gateway cannot see: it sees lookups and NTP requests
    r"|\b(?:did not|didn't|could not|couldn't|never) (?:check|set|sync|update)s? its clock\b",
    re.IGNORECASE,
)


def test_no_red_lines_plain_sentence_claims_what_the_gateway_cannot_see():
    """(pass 4) The plain sentence of the clock red line read "The TV did not check its clock while it
    was on.", and the blocked line's "The TV could not set its clock": the gateway sees lookups of the
    clock hosts and, since the NTP count, the TV's NTP, never what the TV did with its clock."""
    for prefix, _tier, sentence, _action in plain.RED_LINE_PLAIN:
        assert not ABSENCE.search(sentence), (prefix, sentence)
    for old in ("The TV did not check its clock while it was on.", "The TV could not set its clock."):
        assert ABSENCE.search(old)  # the old words, which the test refuses


@pytest.mark.parametrize(("requests", "says_ntp"), [(0, False), (1, True), (12, True)])
def test_a_day_without_a_clock_lookup_says_whether_the_tv_asked_a_time_server(lg, requests, says_ntp):
    """The clock red line fires on a whole day with the TV on and no lookup of its clock hosts. When the
    NTP count saw requests that day, the line says how many, and the plain sentence that the clock may
    still be right; either way it says what the gateway saw, never that the clock was not set."""
    o = {
        **measured_day(),
        "tvstate": [{"time": "18:20", "power": "Active", "app": "netflix"}],
        "clock": {"lookups": 0, "blocked": 0, "first": None, "hosts": list(lg.clock_hosts)},
        "ntp": {"counted": True, "requests": requests, "servers": []},
        "coverage": {
            "not_assessed": [],
            "warnings": [],
            "sources": {"dns": {"rows": 9}, "flows": {"rows": 9}},
        },
    }
    (line,) = [x for x in queries.red_lines(o) if "clock host" in x]
    assert (f"though it sent {requests} NTP request" in line) == says_ntp
    t, sentence, _ = plain.tier(line)
    assert t == "doctor" and sentence.startswith("The gateway saw no lookup of the TV's clock service")
    assert ("may still be right" in sentence) == says_ntp
    plain_lines = plain.plain_brief({**o, "red_lines": queries.red_lines(o)}, None, None, profile=lg)
    for text in [line, *plain_lines]:
        assert not ABSENCE.search(text), text


@pytest.mark.parametrize(
    "cats",
    [
        [],  # the TV asked for nothing at all
        [("Streaming", 266, 0), ("LG core", 300, 0)],  # nothing in the tracking categories
        [("3rd-party ads", 10, 10), ("LG telemetry", 5, 5)],  # every tracking lookup refused
        [("ACR", 3, 3)],
    ],
)
def test_no_form_of_the_brief_says_there_was_no_tracking(lg, cats):
    """(pass 4) The brief counts lookups of known tracking names, and nothing else about tracking can be
    seen from the TV's side of the gateway. So no line, on a day with none of them or with every one
    refused, says or implies that no tracking happened: the plain form says "by name", and neither
    form has a sentence of absence. It failed on the plain form's "asked for no known tracking
    service." before the words "by name"."""
    o = measured_day()
    o["categories"] = [
        {"category": c, "lookups": n, "blocked": b, "names": 1, "conns": 0, "bytes_up": 0, "bytes_down": 0}
        for c, n, b in cats
    ]
    plain_lines = plain.plain_brief(o, plain.activity_from_readings(o), None, profile=lg)
    rich = {**full_brief(), "categories": o["categories"]}
    out = io.StringIO()
    cli.render_brief(rich, out)
    for line in [*plain_lines, *out.getvalue().splitlines()]:
        assert not ABSENCE.search(line), line
    tv = plain_lines[2]
    if not any(plain.is_tracking(c) and n for c, n, _ in cats):
        assert tv.endswith("It asked for no known tracking service by name.")
    assert ABSENCE.search("It asked for no known tracking service.")  # the old words, which the test refuses


def test_new_names_only_new_domains_firmware_and_a_newer_release():
    o = measured_day()
    o["new_hosts"] = [
        {"name": "rr1---sn-a.googlevideo.com", "new_domain": 0},  # churn under a known domain
        {"name": "a.tracker.example", "new_domain": 1},
        {"name": "b.tracker.example", "new_domain": 1},
        *({"name": f"x.n{i}.example", "new_domain": 1} for i in range(4)),
    ]
    o["firmware_changes"] = [{"firmware": "04.70.10"}]
    assert plain.plain_brief(o, None, "0.3.0")[4] == (
        "  New: the TV's software updated to 04.70.10; the TV used 5 new services (tracker.example,"
        " n0.example, n1.example and 2 more); tvgw 0.3.0 is available."
    )


def test_a_list_update_that_took_content_away_is_news_and_one_without_content_is_not():
    o = measured_day()
    o["list_changes"] = {
        "newly_blocked": [{"name": f"media{i}.example", "content": True} for i in range(5)]
        + [{"name": "beacon.example", "content": False}],
        "newly_allowed": [],
    }
    assert plain.plain_brief(o)[4] == (
        "  New: a blocklist update now blocks media0.example, media1.example, media2.example and 2 more,"
        " which the TV downloaded from."
    )


def test_the_new_line_names_the_company_behind_a_name_where_the_snapshot_knows_one(lg):
    """(companies) A new service, and a name a list update took away, carry the company behind them from
    the shipped snapshot of AdGuard's companies database; a name it does not list stays as it was."""
    o = measured_day()
    o["new_hosts"] = [
        {"name": "x.alphonso.tv", "new_domain": 1},
        {"name": "a.tracker.example", "new_domain": 1},
        {"name": "api.samba.tv", "new_domain": 1},
    ]
    o["list_changes"] = {"newly_blocked": [{"name": "nflxvideo.net", "content": True}], "newly_allowed": []}
    assert plain.plain_brief(o, profile=lg)[4] == (
        "  New: the TV used 3 new services (alphonso.tv (LG Group), tracker.example, samba.tv (Free Stream"
        " Media Corp. dba Samba TV)); a blocklist update now blocks nflxvideo.net (Netflix, Inc.), which the TV"
        " downloaded from."
    )


def test_a_day_with_no_known_company_prints_what_it_printed_before(lg, monkeypatch):
    """(companies) The brief of a day whose names the snapshot does not list is the brief without the
    snapshot, line for line: the golden days above, and the same day under an empty table."""
    from tvgw import companies

    days = [measured_day(), full_brief()]
    with_snapshot = [plain.plain_brief(o, plain.activity_from_readings(o), profile=lg) for o in days]
    monkeypatch.setattr(companies, "snapshot", lambda: ({}, {}))
    assert [plain.plain_brief(o, plain.activity_from_readings(o), profile=lg) for o in days] == with_snapshot
    o = measured_day()
    o["new_hosts"] = [{"name": "x.alphonso.tv", "new_domain": 1}]
    assert plain.plain_brief(o, profile=lg)[4] == "  New: the TV used 1 new service (alphonso.tv)."


def test_the_brief_command_prints_the_company_through_the_terminal_cleaner(capsys, store, monkeypatch, lg):
    """(companies) The plain brief on the terminal carries the company, and a name in the snapshot's
    file cannot steer the terminal: every line passes through cli.clean()."""
    from tvgw import companies

    o = measured_day()
    o["new_hosts"] = [{"name": "x.alphonso.tv", "new_domain": 1}, {"name": "odd.example", "new_domain": 1}]
    monkeypatch.setattr(queries, "brief", lambda *a, **k: o)
    monkeypatch.setattr(
        companies, "snapshot", lambda: ({}, {"alphonso.tv": "LG Group", "odd.example": "Bad\x1b[2J"})
    )
    out = run(capsys, store, "brief", "2026-11-04", "--plain")
    assert "alphonso.tv (LG Group), odd.example (Bad\\x1b[2J))" in out and "\x1b" not in out


def test_what_the_brief_cannot_vouch_for_follows_the_action_and_is_no_action(lg):
    """Design section 2.5: when the report carries `not_checked` (the TV's Wi-Fi, which nothing reads and
    the owner has not confirmed off), the plain brief says so after the Action line, and the action that
    action.txt keeps is unchanged."""
    sentence = "the TV's Wi-Fi. When you have switched it off on the TV, run: sudo tvgw tv confirm wifi-forgotten yes"
    o = {**measured_day(), "not_checked": [sentence]}
    lines = plain.plain_brief(o, profile=lg)
    assert lines[5:] == [
        "  Action: nothing needs your attention.",
        f"  Not checked: {sentence}.",
        plain.FOOTER,
    ]
    assert plain.action(o, lg) is None
    assert len(plain.plain_brief(measured_day(), profile=lg)) == 7  # a report without the key


def test_a_store_younger_than_a_day_prints_the_first_day_line():
    assert plain.plain_brief(measured_day(), first=True) == [
        "tvgw brief, Wednesday 4 November (yesterday, 24 hours)",
        f"  {plain.FIRST_DAY}",
        plain.FOOTER,
    ]
    assert plain.first_day(None, NOW) and plain.first_day(NOW - 6 * 3600, NOW)
    assert not plain.first_day(NOW - DAY, NOW)


def test_protection_when_unchecked_mostly_failed_or_checked_part_of_the_day():
    o = measured_day()
    lines = []
    for fw in ({"runs": 0}, {"runs": 10, "failed": 6, "expected": 144}, {"runs": 60, "expected": 144}):
        lines.append(plain.plain_brief({**o, "firewall": fw})[1])
    assert lines == [
        "  Protection: not checked (the gateway recorded no self-checks).",
        "  Protection: failed for most of the day (6 of 10 checks failed).",
        "  Protection: held whenever it was checked (60 of 60 checks passed).",
    ]


# ---- every red line has a row --------------------------------------------------------------------------
def _head(node: ast.AST) -> str | None:
    """The literal text a string expression starts with, up to its first substitution."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        head = ""
        for part in node.values:
            if not isinstance(part, ast.Constant):
                break
            head += part.value
        return head
    return None


def red_line_heads() -> list[str]:
    """What every line queries.red_lines() can write starts with: each `out.append` of a string, and the
    ledger's own red lines, which it appends as they come."""
    heads = []
    fn = ast.parse(textwrap.dedent(inspect.getsource(queries.red_lines)))
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "append"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "out"
        ):
            head = _head(node.args[0])
            if head is not None:
                heads.append(head)
            else:  # a name, not a string: only the ledger's lines are appended so
                assert ast.unparse(node.args[0]) == "line", ast.unparse(node)
    section = ast.parse(textwrap.dedent(inspect.getsource(ledger.section)))
    for node in ast.walk(section):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "red_lines"
                    and isinstance(value, ast.ListComp)
                ):
                    heads.append(_head(value.elt))
    return heads


def test_every_red_line_has_a_row_and_every_row_a_red_line():
    """A red line without a row would fall to the doctor tier unnamed; a row that matches no line is a
    line renamed in queries.py and forgotten here."""
    heads = red_line_heads()
    assert len(heads) >= 16
    prefixes = [row[0] for row in plain.RED_LINE_PLAIN]
    for head in heads:
        assert any(head.startswith(p) for p in prefixes), f"no RED_LINE_PLAIN row for {head!r}"
    for p in prefixes:
        assert any(head.startswith(p) for head in heads), f"RED_LINE_PLAIN row {p!r} matches no red line"


def test_every_row_has_a_known_tier_and_says_something_where_it_must():
    for prefix, t, sentence, action in plain.RED_LINE_PLAIN:
        assert t in plain.TIERS, prefix
        if t == "detail":
            assert sentence == action == "", prefix
        else:
            assert sentence.endswith(".") and action, prefix
            assert t == "act" or action == plain.DOCTOR, prefix  # the gateway's trouble is doctor's


def test_the_lines_red_lines_writes_land_in_their_rows(lg):
    """A brief that sets off the TV's red lines, run through queries.red_lines() itself."""
    o = {
        "since": 0,
        "until": DAY,
        "must_allow_blocked": [{"name": "snu.lge.com", "lookups": 2, "rule": None}],
        "acr": {"value": "on", "t": 100},
        "tv_paths": {"network.wifi.state": {"value": "connected", "t": 100}},
        "clock": {"blocked": 3},
        "firewall": {"failed": 1, "runs": 144, "expected": 144, "last_failures": ["FAIL x"]},
        "consent_flips": [{"flag": "acrAllowed", "t": 100}],
        "coverage": {"warnings": ["w"], "sources": {}},
    }
    lines = queries.red_lines(o)
    assert [plain.tier(line)[0] for line in lines] == [
        "doctor",
        "act",
        "act",
        "doctor",
        "doctor",
        "act",
        "detail",
    ]


# ---- the profile: menu paths and category names ------------------------------------------------------
def test_menu_paths_come_from_the_profiles_acr_record():
    assert plain.action_text(plain.MENU_ACR, profile.load("lg-webos")) == (
        "On the TV: Settings > General > Additional Settings > Live Plus: off."
    )
    samsung = plain.action_text(plain.MENU_ACR, profile.load("samsung-tizen"))
    assert samsung.startswith("On the TV: Settings > All Settings > General & Privacy") and samsung.endswith(
        "Viewing Information Services: off."
    )
    bare = profile.from_dict({"profile": {"name": "bare"}, "categories": {"Streaming": ["x.example"]}})
    assert plain.action_text(plain.MENU_ACR, bare) == plain.GENERIC_SETTING
    assert plain.action_text(plain.MENU_ACR, None) == plain.GENERIC_SETTING


def test_category_names_in_plain_words_and_the_profiles_own():
    lg = profile.load("lg-webos")
    assert [plain.category_label(c, lg) for c in ("LG ads", "LG telemetry", "LG fingerprint", "LG core")] == [
        "LG advertising",
        "LG usage reporting",
        "device fingerprinting",
        "LG's own services",
    ]
    assert plain.category_label("Samsung ads") == "Samsung advertising"
    assert plain.category_label("ACR suspected (shared AWS)") == "ACR suspected (shared AWS)"
    assert plain.is_tracking("ACR suspected (shared AWS)") and not plain.is_tracking("LG IoT")
    data = {
        "profile": {"name": "x"},
        "categories": {"ACR": ["acr.example"], "Odd ads": ["odd.example"]},
        "category_labels": {"Odd ads": "the odd company's adverts", "Other": "everything else"},
    }
    own = profile.from_dict(data)
    assert plain.category_label("Odd ads", own) == "the odd company's adverts"
    assert plain.category_label("Other", own) == "everything else"
    assert profile.from_dict({**data, "category_labels": {}}).category_labels == {}


@pytest.mark.parametrize(
    ("labels", "why"),
    [
        ({"Nope": "x"}, "category_labels.Nope: not a category"),
        ({"ACR": ""}, "category_labels.ACR: expected a non-empty string"),
        ({"ACR": 3}, "category_labels.ACR: expected a non-empty string"),
    ],
)
def test_category_labels_refuse_what_the_brief_would_misread(labels, why):
    with pytest.raises(ValueError, match=why):
        profile.from_dict(
            {"profile": {"name": "x"}, "categories": {"ACR": ["a.example"]}, "category_labels": labels}
        )


def test_every_bundled_profile_still_loads():
    for name in profile.bundled_names():
        assert isinstance(profile.load(name).category_labels, dict)


# ---- the CLI and BRIEF_STYLE ---------------------------------------------------------------------------
@pytest.fixture()
def store(tmp_path):
    """A store with an ingest run three days old, so it is not a first day."""
    path = tmp_path / "s.db"
    c = db.connect(str(path))
    c.execute("INSERT INTO ingest_runs(t, seconds) VALUES (?, 1)", (NOW - 3 * DAY,))
    c.commit()
    c.close()
    return tmp_path


def run(capsys, store, *argv, style=None):
    conf = store / "tvgw.conf"
    conf.write_text(f"BRIEF_STYLE={style}\n" if style else "")
    assert cli.main(["--conf", str(conf), "--db", str(store / "s.db"), *argv]) == 0
    return capsys.readouterr().out


@pytest.fixture()
def rich_day(monkeypatch):
    monkeypatch.setattr(queries, "brief", lambda *a, **k: full_brief())


def golden() -> str:
    """The full brief of the rich fixture, byte for byte, as `render_brief` prints it: the text the
    golden test of test_cli_rich.py holds, line for line, with the tables' padding."""
    out = io.StringIO()
    cli.render_brief(full_brief(), out)
    text = out.getvalue()
    assert [line.rstrip() for line in text.splitlines()] == EVERY_SECTION
    return text


def test_without_brief_style_the_brief_and_the_daily_report_are_todays_golden(capsys, store, rich_day, lg):
    """E-F26: with BRIEF_STYLE absent (or full) `tvgw brief` and `tvgw report --day`, which writes each
    daily file, print exactly the full brief they printed before the plain brief existed."""
    for style in (None, "full"):
        assert run(capsys, store, "brief", "2026-10-26", style=style) == golden()
        assert run(capsys, store, "report", "--day", "2026-10-26", style=style) == golden()
    # the plain style changes `tvgw brief` alone; the report keeps its form without --with-plain
    assert run(capsys, store, "report", "--day", "2026-10-26", style="plain") == golden()
    expected = plain.plain_brief(full_brief(), plain.activity_from_readings(full_brief()), profile=lg)
    assert run(capsys, store, "brief", "2026-10-26", style="plain").splitlines() == expected
    assert run(capsys, store, "brief", "2026-10-26", "--full", style="plain") == golden()
    assert run(capsys, store, "brief", "2026-10-26", "--plain").splitlines() == expected


def test_the_daily_report_with_the_plain_brief_first(capsys, store, rich_day, lg):
    out = run(capsys, store, "report", "--day", "2026-10-26", "--with-plain")
    expected = plain.plain_brief(full_brief(), plain.activity_from_readings(full_brief()), profile=lg)
    assert out == "\n".join(expected) + "\n\n" + golden()


def test_a_days_json_always_carries_its_plain_brief_and_the_brief_json_does_not(capsys, store, rich_day):
    day = json.loads(run(capsys, store, "report", "--day", "2026-10-26", "--json"))
    # seven lines and (tripwire) the While off note the rich fixture's standby traffic adds
    assert day["plain"][0] == "tvgw brief, Monday 26 October 2026 (24 hours)" and len(day["plain"]) == 8
    assert "plain" not in json.loads(run(capsys, store, "brief", "2026-10-26", "--json"))
    week = json.loads(run(capsys, store, "report", "--week", "2026-W44", "--json"))
    assert "plain" not in week


def test_with_plain_goes_with_a_day(capsys, store):
    conf = store / "tvgw.conf"
    conf.write_text("")
    assert cli.main(["--conf", str(conf), "--db", str(store / "s.db"), "report", "--with-plain"]) == 2
    assert "--with-plain goes with --day" in capsys.readouterr().err


def test_the_forms_of_the_brief_exclude_each_other(capsys, store):
    with pytest.raises(SystemExit) as e:
        cli.main(["--conf", str(store / "none.conf"), "brief", "--plain", "--full"])
    assert e.value.code == 2


def test_the_action_line_is_tier_tab_text_or_nothing(capsys, store, monkeypatch, lg):
    o = {**measured_day(), "red_lines": ["Live Plus (ACR) is on on the TV (since x): y"]}
    monkeypatch.setattr(queries, "brief", lambda *a, **k: o)
    assert run(capsys, store, "brief", "2026-11-04", "--action") == (
        "act\tLive Plus (LG's viewing-data collection) is on. On the TV: Settings > General > Additional"
        " Settings > Live Plus: off.\n"
    )
    monkeypatch.setattr(queries, "brief", lambda *a, **k: measured_day())
    assert run(capsys, store, "brief", "2026-11-04", "--action") == ""


def test_a_store_of_six_hours_prints_the_first_day_line_and_no_action(capsys, tmp_path, monkeypatch):
    path = tmp_path / "s.db"
    c = db.connect(str(path))
    c.execute("INSERT INTO ingest_runs(t, seconds) VALUES (?, 1)", (NOW - 6 * 3600,))
    c.commit()
    c.close()
    out = run(capsys, tmp_path, "brief", "--plain").splitlines()
    assert out[1:] == [f"  {plain.FIRST_DAY}", plain.FOOTER]
    o = {**measured_day(), "red_lines": ["Live Plus (ACR) is on on the TV (since x): y"]}
    monkeypatch.setattr(queries, "brief", lambda *a, **k: o)
    assert run(capsys, tmp_path, "brief", "2026-11-04", "--action") == ""


def test_text_from_the_tv_is_cleaned_on_the_plain_lines(capsys, store, monkeypatch):
    o = {**measured_day(), "firmware_changes": [{"firmware": "evil\x1b[2J"}]}
    monkeypatch.setattr(queries, "brief", lambda *a, **k: o)
    out = run(capsys, store, "brief", "2026-11-04", "--plain")
    assert "\x1b" not in out and "evil\\x1b[2J" in out


# ---- tvgw-analyze ----------------------------------------------------------------------------------------
ANALYZE = (ROOT / "deploy" / "bin" / "tvgw-analyze").read_text()
# GNU date as tvgw-analyze calls it, at 2026-11-05 10:00 in the test's zone: `+FMT`, and `-d "DAY [+-N
# days]" +FMT`, where %s is the epoch
DATE_STUB = """#!{python}
import re, sys
from datetime import datetime, timedelta
args = sys.argv[1:]
when = datetime(2026, 11, 5, 10, 0)
if args[0] == "-d":
    m = re.fullmatch(r"(\\d{{4}}-\\d{{2}}-\\d{{2}})(?: ([+-]\\d+) days?)?", args[1])
    when = datetime.strptime(m.group(1), "%Y-%m-%d") + timedelta(days=int(m.group(2) or 0))
    args = args[2:]
print(int(when.timestamp()) if args[0] == "+%s" else when.strftime(args[0][1:]))
"""


def reports_block() -> str:
    """tvgw-analyze from its report writer to its end: the part that writes the files."""
    return ANALYZE[ANALYZE.index("# write PREFIX") :]


@pytest.mark.parametrize("style", [None, "full", "plain"])
def test_the_daily_files_gain_the_plain_brief_only_with_brief_style_plain(tmp_path, style):
    """The job runs with a stub tvgw that prints its arguments and a fixed date: with the key absent the
    daily file is what `tvgw report --day` printed, as before; with plain the report is asked for the
    plain brief first. The action file comes from the newest daily file, as `tvgw brief DAY --action`
    printed it, and is rewritten only when that file is newer."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not installed here")
    stub = tmp_path / "bin"
    stub.mkdir()
    calls = tmp_path / "calls"
    (stub / "tvgw").write_text(
        "#!/bin/sh\n"
        f'echo "$*" >>{calls}\n'
        'case "$1" in\n'
        "  sql) echo 1793000000 ;;\n"  # the store's oldest lookup, before every day of the loop
        '  brief) printf "act\\tturn it off\\n" ;;\n'
        '  report) echo "report $*" ;;\n'
        "esac\n"
    )
    (stub / "date").write_text(DATE_STUB.format(python=sys.executable))
    for f in stub.iterdir():
        f.chmod(0o755)
    reports = tmp_path / "reports"
    (reports / "daily").mkdir(parents=True)
    (reports / "weekly").mkdir()
    script = (
        (f"BRIEF_STYLE={style}\n" if style else "")
        + f"REPORTS={reports}\nSETTLE=10800\nwritten=()\n"
        + reports_block().replace("/usr/local/bin/tvgw", str(stub / "tvgw"))
    )
    env = {"PATH": f"{stub}:/usr/bin:/bin", "TZ": "America/Chicago"}
    out = subprocess.run([bash, "-euo", "pipefail", "-c", script], env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    daily = (reports / "daily" / "2026-11-04.txt").read_text()
    extra = " --with-plain" if style == "plain" else ""
    assert daily == f"report report --day 2026-11-04{extra}\n"
    assert (
        reports / "daily" / "2026-11-04.json"
    ).read_text() == f"report report --day 2026-11-04{extra} --json\n"
    assert (reports / "action.txt").read_text() == "act\tturn it off\n"
    asked = calls.read_text().splitlines()
    assert asked.count("brief 2026-11-04 --action") == 1  # the newest day only
    # a second run writes no daily file and leaves the action file, now newer than the daily file
    calls.unlink()
    subprocess.run([bash, "-euo", "pipefail", "-c", script], env=env, check=True, capture_output=True)
    assert not any(line.startswith("brief") for line in calls.read_text().splitlines())
