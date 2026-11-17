"""(admit) The admission check (design decision 104): what AdGuard would answer before and after a change,
judged against the names the TV must reach and against what the change says it does, reported and never
refusing. The profiles are the bundled ones; every list line here is written for the test (the lists are
GPL-3.0 and their text never enters the repository)."""

import dataclasses
import io
from pathlib import Path

import pytest
from test_profile_property import GAPS, MACHINE, candidates
from test_profile_property import protected as promised

from tvgw import (
    adguardcfg,
    aghinstall,
    cli,
    db,
    ingest,
    ledger,
    listguard,
    listpause,
    localrules,
    policy,
    profile,
    protected,
    queries,
    resolver,
)
from tvgw.config import Settings
from tvgw.listguard import BLOCKED, Client, Engine, parse
from tvgw.policy import Declared

GW, TV = "10.10.10.1", "10.10.10.17"
CLIENT = Client(TV, "tv")
TRACKING = "https://lists.example/tracking.txt"
OTHER = "https://lists.example/other.txt"


def own(prof: profile.Profile, *extra: str) -> list[str]:
    """AdGuard's custom rules for the profile as the plan gives them, with `extra` added."""
    return [*prof.adguard_rules(GW, TV), *extra]


def engine(texts: list[str]) -> Engine:
    return Engine([(policy.CUSTOM, [r for t in texts for r in parse(t) or []])], CLIENT)


def used(prof: profile.Profile) -> list[str]:
    """Names the TV looked up: one for each way the profile's expected categories fill."""
    return [n for n in profile.filled_names(prof) if prof.is_expected(n)]


def needed(prof: profile.Profile) -> str:
    """A name the TV looked up that is protected for its category alone, with no other protected name at or
    under it: a block of it hurts that name and no other."""
    others = protected.names(prof)
    return next(n for n in used(prof) if not any(profile.covers(n, p) for p in others))


NOTHING = Declared(policy.MACHINE)


def check(prof, before, after, declared=NOTHING, recent=()) -> policy.Admission:
    return policy.admit(engine(before), engine(after), declared, protected.names(prof, recent), recent)


# ---- what is protected ----------------------------------------------------------------------------------
def test_each_promise_of_the_profile_is_a_protected_name_with_its_reason(lg):
    """Must-allow hosts for every country of the regions, the clock names, the URL filter, each zone and a
    name under it, and an expected-category name the TV used; the first reason holds a name."""
    got = protected.names(lg, ["streaming.example", "cdn.example", needed(lg), "us.lgtvsdp.com"])
    assert {got[n] for n in ("us.lgtvsdp.com", "de.lgtvsdp.com", "gb.nextlgsdp.com")} == {
        protected.MUST_ALLOW
    }
    assert got["zz.lgtvsdp.com"] == protected.CLOCK  # `??` filled with a code no country has
    assert got["ngfts.lge.com"] == got["gfts.lge.com"] == protected.URL_FILTER
    assert got["amagi.tv"] == got["zz-probe.amagi.tv"] == protected.ZONE
    assert got[needed(lg)] == protected.EXPECTED and "cdn.example" not in got
    assert lg.is_expected("us.lgtvsdp.com") and got["us.lgtvsdp.com"] == protected.MUST_ALLOW  # the first
    assert list(dict.fromkeys(got.values())) == [
        protected.MUST_ALLOW,
        protected.CLOCK,
        protected.URL_FILTER,
        protected.ZONE,
        protected.EXPECTED,
    ]


def test_a_clock_pattern_is_filled_for_every_country_of_the_regions(lg):
    """A clock host named by country that no must-allow host repeats is protected in each country."""
    clock_only = dataclasses.replace(
        lg,
        must_allow={},
        must_allow_templates=(),
        clock_hosts=("??.time.example",),
        regions={"eu": ("de", "fr")},
    )
    got = protected.names(clock_only)
    assert {got[f"{cc}.time.example"] for cc in ("de", "fr", "us", "zz")} == {protected.CLOCK}


# ---- what admit names -------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("change", "line"),
    [
        (
            ["||us.lgtvsdp.com^$dnsrewrite=203.0.113.1"],
            "would refuse: `||us.lgtvsdp.com^$dnsrewrite=203.0.113.1` rewrites us.lgtvsdp.com, which the"
            " profile must let through",
        ),
        (
            ["||nextlgsdp.com^$dnsrewrite=203.0.113.1"],
            "would refuse: `||nextlgsdp.com^$dnsrewrite=203.0.113.1` rewrites zz.nextlgsdp.com, which the TV"
            " sets its clock from",
        ),
        (["||net^"], "would refuse: `||net^` blocks aws-prd.net, a zone the profile never blocks whole"),
        (
            ["||*.amagi.tv^"],
            "would refuse: `||*.amagi.tv^` blocks amagi.tv, a zone the profile never blocks whole",
        ),
        (
            ["@@||ngfts.lge.com^$dnsrewrite"],
            "would refuse: the change lifts `||ngfts.lge.com^$dnsrewrite=10.10.10.1` from ngfts.lge.com, which"
            " must stay rewritten to the URL filter",
        ),
        (
            ["||ngfts.lge.com^$dnsrewrite=203.0.113.9,important"],
            "would refuse: `||ngfts.lge.com^$dnsrewrite=203.0.113.9,important` rewrites ngfts.lge.com, which"
            " must stay rewritten to the URL filter",
        ),
    ],
)
def test_a_change_that_hurts_a_protected_name_is_named_once_whatever_it_declares(lg, change, line):
    """The rule's text decides nothing: a rewrite of a must-allow host, a parent of a clock host or of a
    zone, an exception that cancels the URL filter's rewrite, a rewrite of it elsewhere each change what
    AdGuard answers. A zone's apex and the name under it make one line."""
    for declared in (Declared(policy.MACHINE), Declared(policy.OWNER, ("net", "amagi.tv", "ngfts.lge.com"))):
        assert check(lg, own(lg), own(lg, *change), declared).lines.count(line) == 1


def test_a_name_the_tv_needs_is_named_and_one_the_change_declared_is_not(lg):
    """The package's second acceptance: a block of `tracker.example` declaring it has no line; the same
    plan that also blocks `cdn.example` without declaring it has one, naming that name alone."""
    recent = ["tracker.example", "beacon.tracker.example", "cdn.example", "other.test"]
    said = Declared(policy.MACHINE, ("tracker.example",))
    assert check(lg, own(lg), own(lg, "||tracker.example^"), said, recent).ok
    found = check(lg, own(lg), own(lg, "||tracker.example^", "||cdn.example^"), said, recent)
    assert found.lines == (
        "would refuse: `||cdn.example^` blocks cdn.example, which the change did not declare",
    )
    lifted = check(lg, own(lg, "||cdn.example^"), own(lg, "||tracker.example^"), said, recent)
    assert lifted.lines == (
        "would refuse: the change lifts `||cdn.example^` from cdn.example, which the change did not declare",
    )
    hurt = check(lg, own(lg), own(lg, "||tracker.example^", f"||{needed(lg)}^"), said, [*recent, needed(lg)])
    assert len(hurt.lines) == 1 and "category it needs" in hurt.lines[0]  # said once, as what it is


def test_a_declaration_takes_in_the_names_its_rules_block_and_nothing_else():
    said = policy.of_rules(
        policy.MACHINE, ["||a.test^", "||a.test^$important", "||*.b.test^", "/c/", "@@||d.test^"]
    )
    assert said == Declared(policy.MACHINE, ("a.test", "*.b.test"))
    assert said.covers("x.b.test", policy.CUSTOM) and not said.covers("b.test", policy.CUSTOM)
    assert Declared(policy.PAUSE, lists=(TRACKING,)).covers("anything.test", TRACKING)


def test_a_change_that_declares_nothing_is_judged_on_the_protected_names_alone(lg):
    recent = ["cdn.example", needed(lg)]
    found = check(lg, own(lg), own(lg, "||cdn.example^", f"||{recent[1]}^"), Declared(policy.DEPLOY), recent)
    assert len(found.lines) == 1 and recent[1] in found.lines[0] and "category it needs" in found.lines[0]


def test_a_change_that_changes_no_answer_has_no_line(lg):
    """A name already blocked before stays blocked by another rule: what the TV gets is the same."""
    recent = ["tracker.example", *used(lg)]
    block = f"||{used(lg)[0]}^"
    for before, after in ((own(lg), own(lg)), (own(lg, block), own(lg, block + "$important"))):
        assert check(lg, before, after, Declared(policy.OWNER, ("x.test",)), recent).ok


VET_BREADTH = [  # lane L5's admitted cases: each passed the vetting and the gate the analyst ran then
    ("lg-webos", "metrics.attacker.net", "||net^"),
    ("lg-webos", "beacon.attacker.tv", "||tv^"),
    ("lg-webos", "metrics.attacker.net", "||*.net^"),
    ("lg-webos", "metrics.attacker.net", r"/(lge\.com|aws-prd\.net|amagi\.tv|attacker\.net)$/"),
    ("lg-webos", "metrics.attacker.net", r"/^[[:alnum:]-]+\.lgtvcommon\.com$|^metrics\.attacker\.net$/"),
    ("generic-tv", "metrics.attacker.net", "||*^"),
    ("generic-tv", "metrics.attacker.net", "/./"),
    ("roku", "metrics.attacker.net", "||net^"),
    ("samsung-tizen", "ntp.attacker.org", "||org^"),
    ("vizio-smartcast", "beacon.attacker.tv", "||tv^"),
]


@pytest.mark.parametrize(("name", "heading", "rule"), VET_BREADTH)
def test_every_rule_wider_than_its_heading_is_named(name, heading, rule):
    """Before decision 104 no code judged a rule by what it does: each of these went past the checks that
    read its text. Fed as the plan after a machine rule declaring its heading, each is named, or (a
    POSIX class, which Go and Python read differently) said to be unread."""
    prof = profile.load(name)
    recent = [heading, *used(prof)]
    found = policy.judge(
        Settings(tv_ip=TV, tv_name="tv"),
        prof,
        Declared(policy.MACHINE, (heading,)),
        {"user_rules": own(prof)},
        {"user_rules": own(prof, rule)},
        recent,
    )
    assert found.lines or found.unread == ((rule,) if "[:" in rule else ())
    assert found.unread == ((rule,) if "[:" in rule else ())


@pytest.mark.parametrize("name", profile.bundled_names())
def test_every_rule_the_plain_lint_lets_take_a_zone_or_a_clock_host_is_named(name):
    """The lint a profile's own apply runs reads a rule's text, and on four profiles it lets through 87
    rules that take a never-block zone whole or block a clock host (decision 102 measured them). Run
    against the engine, each one is named by the admission check."""
    prof = profile.load(name)
    guarded = protected.names(prof)
    before = engine(own(prof))
    harmful = named = 0
    for rule in candidates(prof, promised(prof)):
        if dataclasses.replace(prof, custom_rules=(*prof.custom_rules, rule)).lint():
            continue
        after = Engine(
            [(policy.CUSTOM, [r for t in own(prof) for r in parse(t) or []]), (MACHINE, parse(rule))], CLIENT
        )
        breaks = any(
            after.decide(n).state == BLOCKED and after.decide(n).hit.source == MACHINE
            for n in [*(protected.ZONE_PROBE + a for a in prof.never_block_apex), *promised(prof)["clock"]]
        )
        found = policy.admit(before, after, Declared(policy.MACHINE), guarded, ())
        harmful += breaks
        named += breaks and not found.ok
    assert named == harmful and (harmful > 0) == (name in GAPS)


# ---- the engines --------------------------------------------------------------------------------------------
def yaml_with(rules: list[str], *lists: tuple[int, str, bool]) -> dict:
    return {
        "user_rules": rules,
        "filters": [{"id": i, "url": url, "name": f"list {i}", "enabled": on} for i, url, on in lists],
    }


def test_a_pause_declares_its_lists_and_a_list_it_did_not_declare_is_named(tmp_path, monkeypatch):
    """A list switched off lets its names through: declared, no line; another list switched off with it
    is named. Each list file is read once for both engines, and one not downloaded yet holds nothing."""
    (tmp_path / "1.txt").write_text("||tracker.example^\n")
    (tmp_path / "2.txt").write_text("||ads.example^\n")
    reads = []
    real = listguard._lines
    monkeypatch.setattr(listguard, "_lines", lambda path: reads.append(path) or real(path))
    current = yaml_with([], (1, TRACKING, True), (2, OTHER, True), (3, "https://lists.example/new.txt", True))
    recent = ["tracker.example", "ads.example"]
    pause = Declared(policy.PAUSE, lists=(TRACKING,))
    for off, lines in (
        ((TRACKING,), ()),
        (
            (TRACKING, OTHER),
            (
                "would refuse: the change lifts `||ads.example^` from ads.example, which the change did not declare",
            ),
        ),
    ):
        reads.clear()
        planned = yaml_with([], *((i, u, u not in off) for i, u in ((1, TRACKING), (2, OTHER))))
        before, after = policy.engines(current, planned, str(tmp_path), CLIENT, recent)
        assert policy.admit(before, after, pause, {}, recent).lines == lines
        assert sorted(reads) == [str(tmp_path / f"{i}.txt") for i in (1, 2, 3)]


def test_a_pauses_end_is_not_judged_for_what_its_own_list_blocks_and_a_deploy_that_adds_the_list_is(
    tmp_path, lg
):
    """A tracker list that blocks a name the TV needs is the list guard's finding; its coming back at a
    pause's end would otherwise be a line every time, and refusing it would leave the lists off."""
    (tmp_path / "1.txt").write_text(f"||{needed(lg)}^\n")
    off, on = yaml_with(own(lg), (1, TRACKING, False)), yaml_with(own(lg), (1, TRACKING, True))
    guarded = protected.names(lg, [needed(lg)])
    pause = Declared(policy.PAUSE, lists=(TRACKING,))
    before, after = policy.engines(off, on, str(tmp_path), CLIENT, guarded)
    assert policy.admit(before, after, pause, guarded, ()).ok
    (line,) = policy.admit(before, after, Declared(policy.DEPLOY), guarded, ()).lines
    assert line.startswith(f"would refuse: `||{needed(lg)}^` blocks {needed(lg)}")
    on["user_rules"].append("@@||ngfts.lge.com^$dnsrewrite")  # a rule beside the list is judged all the same
    before, after = policy.engines(off, on, str(tmp_path), CLIENT, guarded)
    (lifted,) = policy.admit(before, after, pause, guarded, ()).lines
    assert lifted.endswith("from ngfts.lge.com, which must stay rewritten to the URL filter")


def test_a_check_judges_the_tvs_names_it_is_given(site, lg):
    """The names of the last 14 days decide the undeclared lines: given, they are not read again."""
    said = Declared(policy.MACHINE, ("tracker.example",))
    plan = {"user_rules": own(lg, "||tracker.example^", "||cdn.example^")}
    found = policy.judge(site, lg, said, {"user_rules": own(lg)}, plan, ["cdn.example"])
    assert found.lines == (
        "would refuse: `||cdn.example^` blocks cdn.example, which the change did not declare",
    )
    assert policy.judge(site, lg, said, {"user_rules": own(lg)}, plan).ok  # the store holds no name yet


def test_a_list_file_is_read_when_the_check_runs_never_from_an_earlier_one(tmp_path):
    """No engine is kept between two applies: a list AdGuard downloaded again is judged as it is now."""
    current = yaml_with(["||x.test^"], (1, TRACKING, True))
    for text, state in (("||tracker.example^\n", BLOCKED), ("@@||tracker.example^\n", "allowed")):
        (tmp_path / "1.txt").write_text(text)
        before, _ = policy.engines(current, current, str(tmp_path), CLIENT, ["tracker.example"])
        assert before.decide("tracker.example").state == state


# ---- the hook in the apply -------------------------------------------------------------------------------
@pytest.fixture()
def site(tmp_path):
    s = Settings(
        tv_ip=TV,
        tv_name="tv",
        admit=policy.REPORT,
        state_dir=str(tmp_path),
        db_path=str(tmp_path / "tvgw.db"),
        adguard_yaml=str(tmp_path / "AdGuardHome.yaml"),
        adguard_querylog=str(tmp_path / "data" / "querylog.json"),
        local_rules=str(tmp_path / "local.rules"),
        auto_rules=str(tmp_path / "auto.rules"),
    )
    Path(s.adguard_yaml).write_text(adguardcfg.dump_yaml({"schema_version": 34}), encoding="utf-8")
    return s


def staged(path: str, d: adguardcfg.Desired, admit=None) -> list[str]:
    """`adguardcfg.apply` with every system call stood in for: the file is written, nothing is started."""
    return adguardcfg.apply(
        path,
        d,
        control=lambda *a: None,
        ready=lambda: True,
        check=lambda p: (True, ""),
        guard=lambda: None,
        admit=admit,
    )


def spooled(s: Settings) -> list[ledger.Change]:
    lines = Path(ledger.spool_path(s)).read_text(encoding="utf-8").splitlines()
    return [ledger._spool_row(line.split("\t"), s, None) for line in lines]


def broken_judge(*a, **k):
    raise RuntimeError("the model met a rule it could not hold")


@pytest.mark.parametrize(
    ("admit", "judged"),
    [
        (None, None),  # ADMIT=off: no check at all
        ("report", ledger.ADMIT_REFUSE),
        ("raises", ledger.ADMIT_UNJUDGED),
        ("meddles", None),
    ],
)
def test_report_writes_the_file_off_writes_byte_for_byte_whatever_the_check_does(
    site, lg, tmp_path, monkeypatch, capsys, admit, judged
):
    """The YAML written and what the apply returns are the same with the check off, reporting, raising,
    or changing what it was handed; a fault of the check is one ledger line saying it could not judge."""
    d = adguardcfg.desired(dataclasses.replace(lg, custom_rules=(*lg.custom_rules, "||net^")), site)
    reference = tmp_path / "off.yaml"
    reference.write_text(Path(site.adguard_yaml).read_text(encoding="utf-8"), encoding="utf-8")
    expected = staged(str(reference), d)
    hook = {
        None: None,
        "report": policy.reporter(site, lg, Declared(policy.DEPLOY)),
        "raises": policy.reporter(site, lg, Declared(policy.DEPLOY)),
        "meddles": lambda current, planned: planned["user_rules"].append("||meddled.example^"),
    }[admit]
    if admit == "raises":
        monkeypatch.setattr(policy, "judge", broken_judge)
    assert staged(site.adguard_yaml, d, hook) == expected
    assert Path(site.adguard_yaml).read_bytes() == reference.read_bytes()
    err = capsys.readouterr().err
    if judged is None:
        assert not Path(ledger.spool_path(site)).exists() and "admission check" not in err
        return
    (row,) = spooled(site)
    assert (row.kind, row.subject, row.detail["outcome"]) == ("admit", policy.DEPLOY, judged)
    assert row.detail["lines"][0] in err
    if admit == "raises":
        assert row.detail["lines"] == [
            "could not judge: RuntimeError: the model met a rule it could not hold"
        ]
    else:
        assert "`||net^` blocks aws-prd.net" in row.detail["lines"][0]


def test_a_check_that_fails_to_say_what_it_found_still_lets_the_apply_go_on(site, lg, capsys):
    def unwritable(current, planned):
        raise OSError("read-only file system")

    assert staged(site.adguard_yaml, adguardcfg.desired(lg, site), unwritable)
    assert "the admission check could not judge this change (OSError: read-only file system)" in (
        capsys.readouterr().err
    )


@pytest.mark.parametrize(("n", "more"), [(10, []), (12, ["and 2 more"])])
def test_a_long_finding_shows_ten_lines_and_keeps_ten_with_its_count(site, capsys, n, more):
    lines = [
        f"would refuse: `||n{i}.example^` blocks n{i}.example, which the change did not declare"
        for i in range(n)
    ]
    policy.note(site, policy.OWNER, ledger.ADMIT_REFUSE, lines)
    said = [f"tvgw adguard: admission check (report only): {x}" for x in [*lines[:10], *more]]
    assert capsys.readouterr().err.splitlines() == said
    (row,) = spooled(site)
    assert row.detail == {"outcome": ledger.ADMIT_REFUSE, "count": n, "lines": lines[:10]}
    gone = dataclasses.replace(site, state_dir=str(Path(site.state_dir) / "gone"))
    policy.note(gone, policy.OWNER, ledger.ADMIT_REFUSE, lines)  # the record is lost, the apply is not


def test_a_rule_the_change_adds_that_the_model_does_not_read_is_said_not_judged(site, lg):
    """Its effect is unknown, so it is neither passed in silence nor called a refusal; a rule the YAML held
    before the change is no news."""
    hook = policy.reporter(site, lg, None)
    planned = {"user_rules": own(lg, "/(a+)+x/")}
    hook({"user_rules": own(lg)}, planned)
    hook(planned, planned)
    (row,) = spooled(site)
    assert (row.subject, row.detail["outcome"]) == (policy.DEPLOY, ledger.ADMIT_UNJUDGED)
    assert row.detail["lines"] == ["could not judge `/(a+)+x/`: the model does not read it"]


def test_admit_takes_off_and_report_and_no_word_that_would_refuse(tmp_path):
    from tvgw import config

    conf = tmp_path / "tvgw.conf"
    for value in ("off", "report"):
        conf.write_text(f"ADMIT={value}\n")
        assert config.load(conf).admit == value
    for value in ("refuse", "on"):
        conf.write_text(f"ADMIT={value}\n")
        with pytest.raises(ValueError, match=f"ADMIT='{value}' in tvgw.conf: expected one of off, report"):
            config.load(conf)


def test_with_admit_off_the_check_is_never_built(site, lg, monkeypatch):
    monkeypatch.setattr(policy, "judge", broken_judge)
    off = dataclasses.replace(site, admit="off")
    assert policy.reporter(off, lg, Declared(policy.DEPLOY)) is None
    assert staged(off.adguard_yaml, adguardcfg.desired(lg, off), policy.reporter(off, lg, None))


def test_a_re_apply_that_changes_nothing_builds_no_engine(site, lg, monkeypatch):
    """The apply returns before the hook when the plan is what AdGuard holds."""
    d = adguardcfg.desired(lg, site)
    staged(site.adguard_yaml, d)
    monkeypatch.setattr(policy, "engines", lambda *a: pytest.fail("built"))
    assert staged(site.adguard_yaml, d, policy.reporter(site, lg, None)) == []


def test_the_tvs_names_come_from_the_store_read_only_and_a_missing_store_is_none(site, lg):
    assert policy.recent_names(site) == [] and not Path(site.db_path).exists()
    conn = db.connect(site.db_path)
    now = 1793020000.0 + 30 * 86400  # not the tests' frozen clock: the check reads the window it is given
    conn.executemany(
        "INSERT INTO dns(t, qname, qtype, blocked) VALUES (?, ?, 'A', 0)",
        [(now - 3600, "cdn.example"), (now - 60, "cdn.example"), (now - 15 * 86400, "old.example")],
    )
    conn.commit()
    conn.close()
    assert policy.recent_names(site, now) == ["cdn.example"]


# ---- every caller declares -----------------------------------------------------------------------------------
SEAMS = {
    "tvgw block, allow, unallow": (
        lambda s, prof: [
            localrules.block(s, prof, "tracker.example", wait=0),
            localrules.allow(s, prof, "cdn.example", wait=0),
            localrules.remove(s, prof, "cdn.example", localrules.ALLOW, wait=0),
        ],
        [Declared(policy.OWNER, (name,)) for name in ("tracker.example", "cdn.example", "cdn.example")],
    ),
    "tvgw pause": (lambda s, prof: listpause._default_apply(s, prof)((TRACKING,)), None),
    "tvgw resolver set": (lambda s, prof: resolver._apply_with(prof)(s, True), [Declared(policy.RESOLVER)]),
    "tvgw adguard apply": (
        lambda s, prof: cli.main(["--conf", str(Path(s.state_dir) / "none.conf"), "adguard", "apply"]),
        [Declared(policy.DEPLOY)],
    ),
}


@pytest.mark.parametrize("seam", SEAMS)
def test_each_default_seam_declares_what_it_changes_to_the_real_apply(site, lg, monkeypatch, seam):
    """Each default apply runs to the real `adguardcfg.apply` on a YAML of the test's own, with only the
    service, the readiness and the take-over check stood in for, and hands the check its declaration: the
    owner's commands their one name, a pause the profile's tracker lists, a resolver change and a deploy
    nothing."""
    seen = []
    monkeypatch.setattr(policy, "judge", lambda s, prof, said, *a: seen.append(said) or policy.Admission())
    monkeypatch.setattr(adguardcfg, "apply", staged_with := _staging(adguardcfg.apply))
    monkeypatch.setattr(aghinstall, "takeover_evidence", lambda *a, **k: None)
    monkeypatch.setattr(cli.config, "load", lambda path, **kw: dataclasses.replace(site, **kw))
    run, expected = SEAMS[seam]
    run(site, lg)
    expected = expected or [Declared(policy.PAUSE, lists=tuple(u for _, u in lg.tracking_filters()))]
    assert seen == expected and staged_with.calls == len(expected)


def _staging(real):
    """`adguardcfg.apply` as a default seam calls it, run for real with the system calls stood in for and the
    seam's own admission hook kept; it counts its calls."""

    def apply(path, d, **kw):
        apply.calls += 1
        return real(
            path,
            d,
            control=lambda *a: None,
            ready=lambda: True,
            check=lambda p: (True, ""),
            guard=lambda: None,
            admit=kw.get("admit"),
        )

    apply.calls = 0
    return apply


# ---- the ledger and the brief ------------------------------------------------------------------------------------
def test_an_admission_crosses_the_spool_whole_and_a_damaged_one_is_unread(tmp_path):
    s = Settings(state_dir=str(tmp_path))
    lines = [
        f"would refuse: `||x{i}.example^$important` blocks a|b^c, which the change did not declare"
        for i in range(12)
    ]
    fields = ledger.admit_fields(policy.OWNER, ledger.ADMIT_REFUSE, lines)
    assert all(ledger._FIELD.fullmatch(f) for f in fields)
    change = ledger._spool_row(["1793020000", *fields], s, None)
    assert (change.source, change.kind, change.subject) == ("admit", "admit", policy.OWNER)
    assert change.detail == {"outcome": ledger.ADMIT_REFUSE, "count": 12, "lines": lines[:10]}
    assert ledger.KINDS["admit"][:2] == ("B", 1) and "admit" in ledger.GROUPS["Gateway"]
    for damaged in (
        [*fields[:3], "x", *fields[4:]],  # a count that is no number
        [*fields[:2], "maybe", *fields[3:]],  # an outcome no admission has
        [*fields[:4], "!!!!"],  # not base64 once cleaned
        [*fields[:4], "e30"],  # JSON, but not a list
        [*fields[:4], "WzFd"],  # a list, but not of lines
        fields[:4],
    ):
        assert ledger._spool_row(["1793020000", *damaged], s, None) is None, damaged


def test_the_brief_says_how_many_changes_would_have_been_refused_and_the_first_line(tmp_path, lg):
    """One line a day, only when the check wrote a row in the window; a refusal's line comes before a fault's,
    and a count of none is not said."""
    s = Settings(state_dir=str(tmp_path), db_path=str(tmp_path / "tvgw.db"))
    conn = db.connect(s.db_path)
    day = (1793020000.0, 1793106400.0)

    def brief() -> str:
        out = io.StringIO()
        cli.render_brief(queries.window_report(conn, *day, lg), out)
        return out.getvalue()

    def add(t, outcome, line) -> None:
        ledger.append_spool(ledger.spool_path(s), ledger.admit_fields(policy.MACHINE, outcome, [line]), t)
        ledger.load_spool(conn, s, ingest._tail, pytest.fail)

    assert "Admission check" not in brief() and cli.admission_line(None) == ""
    add(1793020100, ledger.ADMIT_UNJUDGED, "could not judge: OSError: x")
    assert (
        "Admission check (report only, nothing was refused): 1 change could not be judged; the first: could not"
        " judge: OSError: x\n"
    ) in brief()
    add(1793020200, ledger.ADMIT_REFUSE, "would refuse: `||net^` blocks aws-prd.net, a zone ...")
    add(1793020300, ledger.ADMIT_REFUSE, "would refuse: second")
    add(1793200000, ledger.ADMIT_REFUSE, "would refuse: the next day")
    assert (
        "Admission check (report only, nothing was refused): 2 changes would have been refused, 1 change could"
        " not be judged; the first: would refuse: `||net^` blocks aws-prd.net, a zone ...\n"
    ) in brief()
    conn.close()
