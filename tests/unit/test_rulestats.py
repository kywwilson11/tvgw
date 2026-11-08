"""(rule use) Design decision 82: what each of the owner's rules and each list did for the TV, from the
store; the allows that let nothing through in 30 days, named with the command that removes them; the
weekly report's section. Hand-seeded stores at invented times, around the suite's frozen now."""

import dataclasses
import json
import os
import random
from datetime import datetime
from pathlib import Path

import pytest
from conftest import NOW

from tvgw import adguardcfg, cli, config, db, listguard, localrules, profile, rulestats
from tvgw.config import Settings

DAY = 86400
PRO, WEBOS, OTHER = 1792975976, 1792975977, 1792975978  # AdGuard's ids for three lists
ALLOWED = "NotFilteredAllowList"
BLOCKED = "FilteredBlockList"
YAML = f"""schema_version: 34
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt
    name: AdGuard's own name for it
    id: {PRO}
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt
    name: x
    id: {WEBOS}
  - enabled: true
    url: https://lists.example/other.txt
    name: Other list
    id: {OTHER}
  - enabled: false
    url: https://lists.example/off.txt
    name: Off list
    id: 7
whitelist_filters: []
user_rules: []
"""


# a block of the profile's own, as the profile gives it to AdGuard (with `$important` since decision 68)
PROFILE_RULE = next(r for r in profile.load("lg-webos").adguard_rules() if r.startswith("||alphonso.tv^"))


def day(t: float) -> str:
    return datetime.fromtimestamp(t).strftime("%Y-%m-%d")


OLD = day(NOW - 90 * DAY)  # 2026-07-28: a comment line's date well past 30 days
RULES = f"""{localrules.HEADER}
! {OLD} tvgw allow: the news app
@@||news.example^$important
! {OLD} tvgw allow: an old sign-in fix
@@||api.example.net^$important
! {day(NOW - 6 * DAY)} tvgw allow: a new app
@@||new.example^$important
! {OLD} tvgw block: home-screen ads
||ads.example^
! {OLD} tvgw block: an old tracker
||quiet.example^
"""


@pytest.fixture
def site(tmp_path):
    s = Settings(
        tv_mac="b4:b2:91:aa:bb:cc",
        tv_name="lgcx",
        state_dir=str(tmp_path / "state"),
        db_path=str(tmp_path / "state" / "tvgw.db"),
        reports_dir=str(tmp_path / "state" / "reports"),
        auto_rules=str(tmp_path / "state" / "auto.rules"),
        local_rules=str(tmp_path / "etc" / "local.rules"),
        adguard_yaml=str(tmp_path / "AdGuardHome.yaml"),
    )
    os.makedirs(s.state_dir)
    os.makedirs(os.path.dirname(s.local_rules))
    Path(s.adguard_yaml).write_text(YAML, encoding="utf-8")
    return s


def lookup(conn, t, name, rule=None, fid=None, blocked=0, reason="NotFilteredNotFound", n=1):
    conn.executemany(
        "INSERT INTO dns(t, qname, qtype, blocked, reason, rule, filter_id) VALUES (?,?,?,?,?,?,?)",
        [(t + i, name, "A", blocked, reason, rule, fid) for i in range(n)],
    )


def held(conn, text, since):
    conn.execute(
        "INSERT INTO rules(kind, text, first_seen, last_seen, removed_at) VALUES ('adguard', ?, ?, ?, NULL)",
        (text, since, NOW - 600),
    )


def runs(conn, *times):
    conn.executemany(
        "INSERT INTO ingest_runs(t, seconds, stats, warnings) VALUES (?, 1, '{}', '[]')",
        [(t,) for t in times],
    )


@pytest.fixture
def store(site):
    """The owner's five rules and 60 days of record: a block that refused names (once by a list's rule of
    the same text, which is the list's), a block that refused nothing, an allow that let names through
    (and a rule of the same name without the modifier, which is not the owner's), an allow whose last
    lookup is 31 days old, and an allow 6 days old that let nothing through."""
    Path(site.local_rules).write_text(RULES, encoding="utf-8")
    conn = db.connect(site.db_path)
    runs(conn, NOW - 60 * DAY, NOW - 600)
    for text in (
        "@@||news.example^$important",
        "@@||api.example.net^$important",
        "||ads.example^",
        "||quiet.example^",
    ):
        held(conn, text, NOW - 60 * DAY)
    held(conn, "@@||new.example^$important", NOW - 6 * DAY)
    allow, block = {"blocked": 0, "reason": ALLOWED}, {"blocked": 1, "reason": BLOCKED}
    lookup(conn, NOW - 1 * DAY, "news.example", "@@||news.example^$important", 0, **allow)
    lookup(
        conn, NOW - 10 * DAY, "cdn.news.example", "@@||news.example^$important", None, **allow
    )  # before 11-07
    lookup(conn, NOW - 2 * DAY, "news.example", "@@||news.example^", 0, **allow)  # not the owner's text
    lookup(conn, NOW - 31 * DAY, "api.example.net", "@@||api.example.net^$important", 0, **allow)
    lookup(conn, NOW - 3 * DAY, "ads.example", "||ads.example^", 0, n=3, **block)
    lookup(conn, NOW - 20 * DAY, "x.ads.example", "||ads.example^", 0, **block)
    lookup(conn, NOW - 3 * DAY, "y.ads.example", "||ads.example^", PRO, **block)  # a list's rule, same text
    conn.commit()
    yield conn
    conn.close()


def by_name(rep):
    return {r["name"] or r["line"]: r for r in rep["rules"]}


# ---- the owner's rules -----------------------------------------------------------------------------------
def test_each_rule_counts_what_it_decided_by_its_exact_text_among_the_custom_rules(site, store, lg):
    rep = rulestats.owner(site, lg, store, NOW)
    rows = by_name(rep)
    assert [w["label"] for w in rep["windows"]] == ["7 days", "30 days"]
    counts = {n: [(w["lookups"], w["names"]) for w in r["windows"]] for n, r in rows.items()}
    assert counts == {
        "news.example": [(1, 1), (2, 2)],  # the NULL list id of an older row counts; the plain @@ does not
        "api.example.net": [(0, 0), (0, 0)],
        "new.example": [(0, 0), (0, 0)],
        "ads.example": [(3, 1), (4, 2)],  # the list's ||ads.example^ is the list's
        "quiet.example": [(0, 0), (0, 0)],
    }
    assert rows["news.example"]["last"] == NOW - DAY
    assert rows["api.example.net"]["last"] == NOW - 31 * DAY
    assert rows["quiet.example"]["last"] is None and rows["new.example"]["last"] is None


def test_an_allow_unused_for_30_days_is_named_with_its_removal_and_nothing_else_is(site, store, lg):
    rep = rulestats.owner(site, lg, store, NOW)
    assert [r["name"] for r in rep["rules"] if r["stale"]] == ["api.example.net"]
    assert rep["stale_allows"] == [
        {
            "name": "api.example.net",
            "line": "Your allow of api.example.net let nothing through in 30 days. If no app needs it any"
            " more, remove it: sudo tvgw unallow api.example.net",
            "remove": "sudo tvgw unallow api.example.net",
        }
    ]
    # nothing was removed: the file and AdGuard's rules are as they were
    assert Path(site.local_rules).read_text(encoding="utf-8") == RULES


def test_an_allow_is_old_enough_only_by_every_source_that_dates_it(site, store, lg):
    """The rule history says AdGuard took the allow again 10 days ago (unallow, then allow): its old
    comment line does not make it 30 days old."""
    store.execute(
        "UPDATE rules SET first_seen = ? WHERE text = '@@||api.example.net^$important'", (NOW - 10 * DAY,)
    )
    assert rulestats.owner(site, lg, store, NOW)["stale_allows"] == []
    # a hand edit: no dated comment line and no rule history, so its age is unknown and it is not judged
    Path(site.local_rules).write_text("@@||api.example.net^$important\n", encoding="utf-8")
    store.execute("DELETE FROM rules")
    rep = rulestats.owner(site, lg, store, NOW)
    assert rep["rules"][0]["in_force_since"] is None and rep["stale_allows"] == []
    # the comment line alone dates it
    Path(site.local_rules).write_text(f"! {OLD} tvgw allow: x\n@@||api.example.net^$important\n")
    assert [x["name"] for x in rulestats.owner(site, lg, store, NOW)["stale_allows"]] == ["api.example.net"]


def test_a_comment_line_dates_a_rule_by_the_end_of_its_day():
    assert rulestats.written_by("! 2026-10-26 tvgw allow: x") == datetime(2026, 10, 27).timestamp()
    assert rulestats.written_by("# 2026-10-26 by hand") == datetime(2026, 10, 27).timestamp()
    assert rulestats.written_by("! tvgw allow: no date") is None
    assert rulestats.written_by("! 2026-13-40 tvgw allow: x") is None
    assert rulestats.written_by("") is None


@pytest.mark.parametrize(
    ("setup", "said"),
    [
        (
            lambda c: c.execute("DELETE FROM ingest_runs WHERE t < ?", (NOW - 20 * DAY,)),
            "less than 30 days before",
        ),
        (
            lambda c: c.execute("DELETE FROM ingest_runs WHERE t > ?", (NOW - 3 * 3600,)),
            "more than 2 hours before",
        ),
        (lambda c: c.execute("DELETE FROM ingest_runs"), "the gateway has no record yet"),
    ],
)
def test_no_allow_is_called_unused_while_the_record_does_not_cover_the_30_days(site, store, lg, setup, said):
    if "more than" in said:
        runs(store, NOW - 4 * 3600)
    setup(store)
    rep = rulestats.owner(site, lg, store, NOW)
    assert rep["stale_allows"] == [] and said in rep["record"]["why_not"]
    lines = rulestats.owner_lines(rep)
    assert f"No allow is called unused yet: {rep['record']['why_not']}." in lines
    assert not any("up to -" in x for x in lines)  # a record never read has no last reading to name


def test_a_record_kept_fewer_than_30_days_judges_no_allow(site, store, lg):
    short = dataclasses.replace(site, db_days=14)
    rep = rulestats.owner(short, lg, store, NOW)
    assert (
        rep["stale_allows"] == []
        and rep["record"]["why_not"] == "the gateway keeps only 14 days of its record"
    )


def test_a_line_the_plan_refuses_is_never_called_unused(site, store, lg):
    """An allow the lint leaves out is not in AdGuard, so it is no hole; the listing says why instead."""
    Path(site.local_rules).write_text(f"! {OLD} tvgw block: x\n||snu.lge.com^\n! {OLD} by hand\nnot a rule\n")
    rep = rulestats.owner(site, lg, store, NOW)
    first, second = rep["rules"]
    assert first["not_applied"].startswith("snu.lge.com is kept reachable on purpose") and not first["stale"]
    assert second["kind"] is None and second["windows"] is None and second["line"] == "not a rule"
    lines = rulestats.owner_lines(rep)
    assert "not applied: snu.lge.com is kept" in lines[1] and lines[2].split()[:3] == ["?", "not", "a"]


def test_an_allow_the_plan_leaves_out_is_never_called_unused(site, store, lg, monkeypatch):
    """An allow the lint refuses never reaches AdGuard, so it is no hole: the listing says it is not
    applied instead (no allow the owner's commands write is refused today, so the lint is stood in for)."""
    refuse = "@@||api.example.net^$important"
    monkeypatch.setattr(
        localrules, "problems", lambda lines, prof: [(x, "refused here") for x in lines if x == refuse]
    )
    rep = rulestats.owner(site, lg, store, NOW)
    assert rep["stale_allows"] == [] and by_name(rep)["api.example.net"]["not_applied"] == "refused here"


def test_only_what_adguard_says_it_allowed_under_the_rule_counts(site, store, lg):
    """A row with the allow's text whose reason is not the allow list's (an older record without a
    numeric reason) is not counted: the store cannot say the allow decided it."""
    lookup(
        store, NOW - DAY, "api.example.net", "@@||api.example.net^$important", 0, reason="NotFilteredNotFound"
    )
    rep = rulestats.owner(site, lg, store, NOW)
    assert by_name(rep)["api.example.net"]["windows"][0]["lookups"] == 0 and rep["stale_allows"]


def test_since_changes_the_window_and_the_30_days_still_judge(site, store, lg):
    rep = rulestats.owner(site, lg, store, NOW, since=NOW - 2 * DAY)
    assert [w["label"] for w in rep["windows"]] == [f"since {rulestats.when(NOW - 2 * DAY)}"]
    rows = by_name(rep)
    assert [(w["lookups"], w["names"]) for w in rows["news.example"]["windows"]] == [(1, 1)]
    assert [x["name"] for x in rep["stale_allows"]] == ["api.example.net"]
    lines = rulestats.owner_lines(rep)
    assert lines[0].split()[:4] == ["kind", "name", "since", rulestats.when(NOW - 2 * DAY).split()[0]]
    assert any(f"Names are the different names since {rulestats.when(NOW - 2 * DAY)}." in x for x in lines)


def test_the_listing_prints_the_counts_the_last_decision_and_the_stale_line(site, store, lg):
    lines = rulestats.owner_lines(rulestats.owner(site, lg, store, NOW))
    assert lines[0].split() == [
        "kind",
        "name",
        "7",
        "days",
        "30",
        "days",
        "names",
        "last",
        "decided",
        "written",
    ]
    rows = {ln.split()[1]: ln for ln in lines[1:6]}
    assert rows["news.example"].split()[:6] == [
        "allow",
        "news.example",
        "1",
        "2",
        "2",
        rulestats.when(NOW - DAY).split()[0],
    ]
    assert f"{OLD} tvgw allow: the news app" in rows["news.example"]
    assert rows["quiet.example"].split()[:7] == ["block", "quiet.example", "0", "0", "0", "not", "seen"]
    assert rows["api.example.net"].rstrip().endswith("nothing let through in 30 days")
    assert lines[-1].startswith("Your allow of api.example.net let nothing through in 30 days.")
    assert lines[-2].startswith("The counts are the TV's lookups each rule decided")


def test_no_file_an_empty_file_and_no_store(site, store, lg):
    rep = rulestats.owner(site, lg, store, NOW)
    os.unlink(site.local_rules)
    absent = rulestats.owner(site, lg, store, NOW)
    assert not absent["exists"] and absent["rules"] == []
    assert rulestats.owner_lines(absent)[0].startswith(f"No site rules: {site.local_rules} does not exist.")
    Path(site.local_rules).write_text(localrules.HEADER + "\n")
    assert rulestats.owner_lines(rulestats.owner(site, lg, store, NOW)) == [
        f"No site rules in {site.local_rules}."
    ]
    Path(site.local_rules).write_text(RULES)
    bare = rulestats.owner(site, lg, None, NOW)  # no store yet
    assert bare["record"] is None and all(r["windows"] is None and not r["stale"] for r in bare["rules"])
    lines = rulestats.owner_lines(bare)
    assert (
        lines[1].split()[2:5] == ["-", "-", "-"]
        and lines[-1] == "The gateway has no record yet, so the counts are not known."
    )
    assert len(rep["rules"]) == len(bare["rules"]) == 5


# ---- what each list did ----------------------------------------------------------------------------------
@pytest.fixture
def week(site, store, lg):
    """Refusals in the last 7 days from every kind of source."""
    block = {"blocked": 1, "reason": BLOCKED}
    profile_rule = PROFILE_RULE
    assert profile_rule in lg.adguard_rules(site.gw_ip, site.tv_ip)
    lookup(store, NOW - DAY, "tracker.example", "||tracker.example^", PRO, n=5, **block)
    lookup(store, NOW - DAY, "printer.lan", "||printer.lan^", PRO, n=9, **block)  # counted, never shown
    for i in range(6):
        lookup(store, NOW - DAY, f"t{i}.example", f"||t{i}.example^", PRO, n=1, **block)
    lookup(store, NOW - DAY, "x.alphonso.tv", profile_rule, 0, n=2, **block)
    lookup(store, NOW - DAY, "gone.example", "||gone.example^", 0, **block)  # an owner's rule taken out since
    lookup(store, NOW - DAY, "m.example", "||m.example^", 0, **block)  # the machine's, reverted since
    lookup(store, NOW - DAY, "drift.example", "||drift.example^", 0, **block)  # in no file of tvgw's
    lookup(store, NOW - DAY, "svc.example", None, -2, blocked=1, reason="FilteredBlockedService")
    lookup(
        store, NOW - DAY, "five.example", "||five.example^", 5, **block
    )  # a list no longer in the settings
    lookup(store, NOW - 9 * DAY, "old.example", "||old.example^", WEBOS, **block)  # outside the window
    lookup(store, NOW - DAY, "fine.example")  # answered
    for verb in ("block", "unblock"):
        store.execute(
            "INSERT INTO changes(t, t_precision, source, kind, subject, detail, controllable, effect_class)"
            " VALUES (?, 1, 'owner', 'owner_rule_change', 'gone.example', ?, 1, 'A')",
            (NOW - 2 * DAY + (verb == "unblock"), json.dumps({"action": verb})),
        )
    store.execute(
        "INSERT INTO auto_rules(rule, name, added_t, verdict) VALUES ('||m.example^', 'm.example', ?, 'reverted')",
        (NOW - 3 * DAY,),
    )
    store.commit()
    return store


def rows_of(rep):
    return {r["label"]: r for r in rep["rows"]}


def test_each_list_and_each_kind_of_rule_gets_its_refusals_and_they_add_up(site, week, lg):
    rep = rulestats.lists(site, lg, week, NOW - 7 * DAY, NOW)
    assert rep["named"] and rep["notes"] == []
    assert [r["label"] for r in rep["rows"]] == [
        "HaGeZi Pro",
        "HaGeZi LG webOS",
        "Other list",
        "list 5",
        "The profile's own rules",
        "Your own rules",
        "The gateway's own rules",
        "Rules none of tvgw's files hold now",
        "AdGuard Home's own features, or no rule named",
    ]
    rows = rows_of(rep)
    assert (rows["HaGeZi Pro"]["refused"], rows["HaGeZi Pro"]["names"]) == (1 + 5 + 9 + 6, 1 + 1 + 1 + 6)
    assert [t["name"] for t in rows["HaGeZi Pro"]["top"]] == [
        "tracker.example",
        "t0.example",
        "t1.example",
        "t2.example",
        "t3.example",
    ]
    assert (rows["HaGeZi LG webOS"]["refused"], rows["Other list"]["refused"]) == (0, 0)
    assert rows["HaGeZi LG webOS"]["sentinel"] and not rows["Other list"]["sentinel"]
    assert rows["The profile's own rules"]["top"] == [
        {"name": "x.alphonso.tv", "lookups": 2, "company": "LG Group"}
    ]
    assert (rows["Your own rules"]["refused"], rows["Your own rules"]["names"]) == (
        3 + 1,
        2,
    )  # ads.example, gone
    assert rows["The gateway's own rules"]["refused"] == 1
    assert rows["Rules none of tvgw's files hold now"]["top"][0]["name"] == "drift.example"
    assert sum(r["refused"] for r in rep["rows"]) == rep["refused"] == 3 + 21 + 2 + 1 + 1 + 1 + 1 + 1
    assert rep["lookups"] == rep["refused"] + 3  # news.example twice and fine.example were answered


def test_a_text_two_sources_hold_stays_with_the_earlier_one_in_the_plan(site, week, lg):
    """As `adguardcfg.rule_groups` keeps it: the profile's rule copied into the owner's file stays the
    profile's, and the owner's block the machine also holds stays the owner's."""
    Path(site.local_rules).write_text(RULES + PROFILE_RULE + "\n")
    Path(site.auto_rules).write_text("||ads.example^\n")
    rows = rows_of(rulestats.lists(site, lg, week, NOW - 7 * DAY, NOW))
    assert rows["The profile's own rules"]["refused"] == 2 and rows["Your own rules"]["refused"] == 4
    assert rows["The gateway's own rules"]["refused"] == 1


def test_a_list_that_refused_nothing_is_said_plainly_with_the_check_that_it_is_loaded(site, week, lg):
    lines = rulestats.list_lines(rulestats.lists(site, lg, week, NOW - 7 * DAY, NOW))
    assert lines[0] == (
        f"From {rulestats.when(NOW - 7 * DAY)} to {rulestats.when(NOW)} (7 days), the filter refused 31 lookups"
        " of the TV's 34."
    )
    assert (
        "HaGeZi LG webOS refused nothing the TV asked for. sudo tvgw verify checks that it is loaded."
        in lines
    )
    assert "Other list refused nothing the TV asked for." in lines
    at = lines.index("HaGeZi Pro refused 21 lookups of 9 names.")
    assert lines[at + 1 : at + 3] == ["  5  tracker.example", "  1  t0.example"]
    assert "  2  x.alphonso.tv (LG Group)" in lines
    assert not any("printer.lan" in x for x in lines)
    assert "The gateway's own rules refused 1 lookup of 1 name." in lines


def test_without_adguards_settings_the_lists_go_by_number_and_say_why(site, week, lg, monkeypatch):
    os.unlink(site.adguard_yaml)
    rep = rulestats.lists(site, lg, week, NOW - 7 * DAY, NOW)
    assert not rep["named"] and [r["label"] for r in rep["rows"][:2]] == [f"list {PRO}", "list 5"]
    assert rep["notes"][0].startswith("The lists are shown by AdGuard Home's number for them, and a list")
    assert "is not there" in rep["notes"][0]

    def refuse(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(adguardcfg, "load_yaml", refuse)
    rep = rulestats.lists(site, lg, week, NOW - 7 * DAY, NOW)
    assert rep["notes"][0].endswith(
        "this account cannot read AdGuard Home's settings file; run it with sudo for the names."
    )
    assert sum(r["refused"] for r in rep["rows"]) == rep["refused"]


def test_a_quiet_window_says_every_row_refused_nothing(site, store, lg):
    rep = rulestats.lists(site, lg, store, NOW - 3600, NOW)
    assert rep["refused"] == 0 and all(r["refused"] == 0 for r in rep["rows"])
    assert [r["label"] for r in rep["rows"]][-3:] == [
        "The profile's own rules",
        "Your own rules",
        "The gateway's own rules",
    ]
    assert rulestats.list_lines(rep)[0].endswith("(1 hour), the filter refused 0 lookups of the TV's 0.")


def test_the_rows_always_add_up_to_the_windows_refusals(site, lg):
    """Property: whatever the lookups, every refusal lands in exactly one row, each owner's rule counts no
    more in 7 days than in 30, and no row has more names than refusals (fixed seed)."""
    Path(site.local_rules).write_text(RULES)
    rng = random.Random(82)
    texts = [
        "||ads.example^",
        "@@||news.example^$important",
        PROFILE_RULE,
        "||m.example^",
        "||x.example^",
        None,
    ]
    ids = [None, 0, PRO, WEBOS, 5, -2]
    for trial in range(25):
        path = Path(site.state_dir) / f"p{trial}.db"
        conn = db.connect(str(path))
        runs(conn, NOW - 40 * DAY, NOW - 60)
        for _ in range(rng.randrange(0, 80)):
            blocked = rng.random() < 0.6
            lookup(
                conn,
                NOW - rng.uniform(0, 40 * DAY),
                rng.choice(["a.example", "b.example", "c.example", "printer.lan"]),
                rng.choice(texts),
                rng.choice(ids),
                blocked=int(blocked),
                reason=BLOCKED if blocked else rng.choice([ALLOWED, "NotFilteredNotFound"]),
            )
        conn.commit()
        since = NOW - rng.uniform(1, 35) * DAY
        rep = rulestats.lists(site, lg, conn, since, NOW)
        assert sum(r["refused"] for r in rep["rows"]) == rep["refused"]
        assert all(r["names"] <= r["refused"] and len(r["top"]) <= rulestats.TOP for r in rep["rows"])
        for r in rulestats.owner(site, lg, conn, NOW)["rules"]:
            (a, b) = r["windows"]
            assert a["lookups"] <= b["lookups"] and a["names"] <= b["names"] <= b["lookups"]
        conn.close()


# ---- the weekly report -----------------------------------------------------------------------------------
def test_the_weekly_section_names_the_stale_allow_and_what_each_list_did(site, week, lg):
    sec = rulestats.weekly(site, lg, week, NOW - 7 * DAY, NOW)
    lines = rulestats.weekly_lines(sec)
    assert lines[0].startswith("Your allow of api.example.net let nothing through in 30 days.")
    assert lines[1].startswith(f"From {rulestats.when(NOW - 7 * DAY)} to")
    assert sec["allows"] == 3 and sec["stale_not_judged"] is None
    # a record kept fewer than 30 days judges no allow, and the section says why
    short = rulestats.weekly(dataclasses.replace(site, db_days=14), lg, week, NOW - 7 * DAY, NOW)
    assert (
        short["stale_allows"] == []
        and short["stale_not_judged"] == "the gateway keeps only 14 days of its record"
    )
    assert (
        rulestats.weekly_lines(short)[0]
        == "No allow is called unused yet: the gateway keeps only 14 days of its record."
    )
    # a week judged at its own end: 29 days after the old allow's last lookup it is not stale yet, and an
    # allow younger than 30 days that let nothing through keeps the section from saying every allow did
    early = rulestats.weekly(site, lg, week, NOW - 3 * DAY, NOW - 2 * DAY)
    assert early["stale_allows"] == [] and early["stale_not_judged"] is None
    assert rulestats.weekly_lines(early)[0].startswith("From ")
    os.unlink(site.local_rules)
    quiet = rulestats.weekly(site, lg, week, NOW - 7 * DAY, NOW)
    assert quiet["allows"] == 0 and rulestats.weekly_lines(quiet)[0].startswith("From ")


def test_every_allow_in_use_is_said_once(site, week, lg):
    Path(site.local_rules).write_text(f"! {OLD} tvgw allow: x\n@@||news.example^$important\n")
    assert rulestats.weekly_lines(rulestats.weekly(site, lg, week, NOW - 7 * DAY, NOW))[0] == (
        "Each of your allows let something through in the last 30 days."
    )


@pytest.fixture
def conf(site, tmp_path, monkeypatch):
    path = tmp_path / "tvgw.conf"
    path.write_text(
        f"STATE_DIR={site.state_dir}\nDB_PATH={site.db_path}\nAUTO_RULES={site.auto_rules}\n"
        f"LOCAL_RULES={site.local_rules}\n"
    )
    load = config.load
    monkeypatch.setattr(
        config, "load", lambda *a, **k: dataclasses.replace(load(*a, **k), adguard_yaml=site.adguard_yaml)
    )
    return str(path)


def test_the_weekly_report_carries_the_section_in_text_and_json(conf, week, capsys):
    week_id = datetime.fromtimestamp(NOW - 3 * DAY).strftime("%G-W%V")
    assert cli.main(["--conf", conf, "report", "--week", week_id]) == 0
    text = capsys.readouterr().out
    assert (
        "\nRule use (what each list and rule refused this week; tvgw lists and tvgw rules --local say" in text
    )
    part = text.split("\nRule use (")[1]
    assert "HaGeZi Pro refused" in part and "Your allow of api.example.net" in part
    assert cli.main(["--conf", conf, "report", "--week", week_id, "--json"]) == 0
    o = json.loads(capsys.readouterr().out)
    assert o["rule_use"]["lists"]["named"] and list(o)[-1] == "rule_use"
    assert [x["name"] for x in o["rule_use"]["stale_allows"]] == ["api.example.net"]


def test_a_rule_use_that_fails_costs_only_its_section(conf, week, capsys, monkeypatch):
    def broken(*a, **k):
        raise OSError("disk gone")

    monkeypatch.setattr(rulestats, "weekly", broken)
    week_id = datetime.fromtimestamp(NOW - 3 * DAY).strftime("%G-W%V")
    assert cli.main(["--conf", conf, "report", "--week", week_id]) == 0
    text = capsys.readouterr().out
    assert "report warning: Rule use could not be computed (OSError: disk gone)" in text
    assert "\nRule use (" not in text and "\nBy day:" in text


def test_a_day_report_has_no_rule_use(conf, week, capsys):
    assert cli.main(["--conf", conf, "report", "--day", day(NOW - DAY), "--json"]) == 0
    assert "rule_use" not in json.loads(capsys.readouterr().out)
    assert cli.main(["--conf", conf, "report", "--day", day(NOW - DAY)]) == 0
    assert "\nRule use (" not in capsys.readouterr().out


# ---- the commands ----------------------------------------------------------------------------------------
def test_rules_local_prints_counts_and_json_and_refuses_misplaced_options(conf, store, capsys):
    assert cli.main(["--conf", conf, "rules", "--local"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split()[:6] == ["kind", "name", "7", "days", "30", "days"]
    assert out[-1].startswith("Your allow of api.example.net")
    assert cli.main(["--conf", conf, "rules", "--local", "--json", "--since", "2d"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert (
        len(rep["windows"]) == 1 and rep["stale_allows"][0]["remove"] == "sudo tvgw unallow api.example.net"
    )
    assert cli.main(["--conf", conf, "rules", "--since", "2d"]) == 2
    assert capsys.readouterr().err == "tvgw rules: error: --since and --json go with --local\n"
    assert cli.main(["--conf", conf, "rules", "--json"]) == 2
    assert (
        cli.main(["--conf", conf, "rules", "--local", "--since", rulestats.when(NOW + DAY).replace(" ", "T")])
        == 2
    )
    assert "--since must be in the past" in capsys.readouterr().err


def test_rules_local_without_a_store_lists_the_rules_and_an_unreadable_file_says_so(
    conf, site, capsys, monkeypatch
):
    Path(site.local_rules).write_text(RULES)
    assert not os.path.exists(site.db_path)
    assert cli.main(["--conf", conf, "rules", "--local"]) == 0
    assert (
        capsys.readouterr().out.splitlines()[-1]
        == "The gateway has no record yet, so the counts are not known."
    )

    def refuse(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(localrules, "read_text", refuse)
    assert cli.main(["--conf", conf, "rules", "--local"]) == 1
    assert capsys.readouterr().out == f"tvgw rules: cannot read {site.local_rules}; run it with sudo\n"
    assert cli.main(["--conf", conf, "rules", "--local", "--json"]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "error": f"tvgw rules: cannot read {site.local_rules}; run it with sudo"
    }


def test_lists_ends_with_the_refusals_by_list_and_keeps_the_list_guards_exit(conf, week, capsys):
    """`tvgw lists` is the list guard's command (design decision 68); the refusals by list are its last
    section, its JSON's `use`, and its exit status stays the guard's."""
    assert cli.main(["--conf", conf, "lists"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("tvgw lists: no scan yet;") and out[1:3] == [
        "",
        "Refusals by list over the last 7 days:",
    ]
    assert "(7 days), the filter refused 31 lookups of the TV's 34." in out[3]
    lists = [{"id": PRO, "name": "HaGeZi Pro", "state": "ok"}]
    week.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
        (listguard.META_KEY, json.dumps({"t": NOW, "lists": lists, "findings": []})),
    )
    week.commit()
    assert cli.main(["--conf", conf, "lists", "--since", "1d"]) == 0
    out = capsys.readouterr().out
    guard, use = out.split("\nRefusals by list over the last 1 day:\n")
    assert "Lists AdGuard Home holds, as scanned" in guard and "No line of these lists acts" in guard
    assert (
        use.startswith("From ") and "HaGeZi Pro refused 20 lookups of 8 names." in use
    )  # y.ads.example: 3 days
    assert cli.main(["--conf", conf, "lists", "--since", "1d", "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert set(rep) == {"state", "previews", "use"} and rep["state"]["lists"] == lists
    assert rep["use"]["refused"] == sum(r["refused"] for r in rep["use"]["rows"]) == 27  # ads.example: 3 days
    lifts = {"kind": "lifts", "list": "HaGeZi Pro", "line": "@@||x.example^", "target": "||x.example^"}
    week.execute(
        "UPDATE meta SET value = ? WHERE key = ?",
        (json.dumps({"t": NOW, "lists": lists, "findings": [lifts]}), listguard.META_KEY),
    )
    week.commit()
    assert cli.main(["--conf", conf, "lists", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["use"]["refused"] == 31
    assert cli.main(["--conf", conf, "lists", "--since", "2h", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["use"]["refused"] == 0


def test_lists_refuses_a_window_that_is_not_in_the_past(conf, week, capsys):
    assert cli.main(["--conf", conf, "lists", "--since", rulestats.when(NOW + DAY).replace(" ", "T")]) == 2
    assert capsys.readouterr().err == "tvgw lists: error: --since must be in the past\n"
    with pytest.raises(SystemExit) as e:
        cli.main(["--conf", conf, "lists", "--since", "soon"])
    assert e.value.code == 2
    with pytest.raises(SystemExit):  # SINCE is an option: a bare window is not taken
        cli.main(["--conf", conf, "lists", "1d"])


def test_every_command_the_lines_name_exists_in_this_version():
    texts = [
        rulestats.STALE_LINE.format(host="api.example.net", days=30),
        "sudo tvgw verify",
        "tvgw lists --since 1d",
        "tvgw rules --local",
    ]
    parser = cli.build_parser()
    for text in texts:
        command = text[text.index("tvgw ") :].removeprefix("tvgw ").split()
        parser.parse_args(command)


def test_span_reads_a_window_in_words():
    assert [rulestats.span(x) for x in (604800.4, 86400, 7200, 5400, 60, 1, 90000)] == [
        "7 days",
        "1 day",
        "2 hours",
        "2 hours",
        "1 minute",
        "1 minute",
        "25 hours",
    ]
