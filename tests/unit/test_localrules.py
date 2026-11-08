"""Site rules (design decision 59): the owner's own allow and block rules, their lint, the commands that
write them, and where they sit in AdGuard's plan."""

import dataclasses
import json
import os
import stat
from pathlib import Path

import pytest
import yaml

from tvgw import adguardcfg, analyst, autoblock, cli, db, forget, ledger, localrules
from tvgw.config import Settings

NOW = 1793020000.0  # 2026-10-26, the fixtures' day


@pytest.fixture
def site(tmp_path):
    """Settings whose files are all under tmp_path: no site rules yet, an empty machine file."""
    return Settings(
        tv_mac="b4:b2:91:aa:bb:cc",
        tv_name="lgcx",
        state_dir=str(tmp_path / "state"),
        db_path=str(tmp_path / "state" / "tvgw.db"),
        reports_dir=str(tmp_path / "state" / "reports"),
        auto_rules=str(tmp_path / "state" / "auto.rules"),
        local_rules=str(tmp_path / "etc" / "local.rules"),
    )


@pytest.fixture(autouse=True)
def dirs(site):
    os.makedirs(site.state_dir, exist_ok=True)


class Applies:
    """Stands in for `tvgw adguard apply`: records the custom rules it would plan, or raises."""

    def __init__(self, site, lg, fail: BaseException | None = None):
        self.site, self.lg, self.fail, self.seen = site, lg, fail, []

    def __call__(self):
        self.seen.append(adguardcfg.user_rules(self.lg, self.site))
        if self.fail is not None:
            raise self.fail
        return ["user_rules: ..."]


def text(site) -> str:
    return Path(site.local_rules).read_text(encoding="utf-8")


def spool(site) -> list[list[str]]:
    path = Path(ledger.spool_path(site))
    return [line.split("\t") for line in path.read_text().splitlines()] if path.exists() else []


# ---- the lint, in both modes ------------------------------------------------------------------------
def test_the_profile_lint_refuses_an_allow_over_a_block_and_the_site_mode_takes_it(lg):
    """lg-webos.rules blocks ibs.lgappstv.com (decision D28's billing host). As a profile rule its
    exception would be a mistake the lint stops; as the owner's allow it is the undo D28 names."""
    allow = "@@||ibs.lgappstv.com^$important"
    with_allow = dataclasses.replace(lg, custom_rules=(*lg.custom_rules, allow))
    assert any("sits above blocked 'ibs.lgappstv.com'" in p for p in with_allow.lint())
    assert with_allow.lint(lifts=frozenset({"ibs.lgappstv.com"})) == lg.lint() == []
    assert localrules.problems([allow], lg) == []
    # at, under and over a blocked name: what an allow is for
    assert localrules.problems(["@@||x.alphonso.tv^$important", "@@||alphonso.tv^$important"], lg) == []


@pytest.mark.parametrize(
    ("rule", "why"),
    [
        ("||snu.lge.com^", "snu.lge.com is kept reachable on purpose: firmware updates"),
        ("||lge.com^", "snu.lge.com is under lge.com, and kept reachable on purpose"),
        ("||lgtvsdp.com^", "us.lgtvsdp.com is under lgtvsdp.com"),
        ("||x.snu.lge.com^", "is under snu.lge.com, which is kept reachable on purpose, so the block"),
        ("||gb.lgtvsdp.com^", "the TV sets its clock from gb.lgtvsdp.com"),
        ("||ngfts.lge.com^", "ngfts.lge.com goes through the URL filter"),
        ("||amagi.tv^", "amagi.tv mixes what the TV needs with what it reports"),
        ("||*.example^", "a site rule is @@||name^$important (allow) or ||name^ (block)"),
        ("/ads?\\./", "a site rule is"),
        ("||ads.example^$important", "a site rule is"),
        ("@@||ads.example^", "a site rule is"),
        ("@@||ads.example^$dnsrewrite=192.0.2.1", "a site rule is"),
        ("0.0.0.0 ads.example", "a site rule is"),
    ],
)
def test_the_lint_refuses_what_the_tv_needs_and_every_other_form(lg, rule, why):
    ((got, reason),) = localrules.problems([rule], lg)
    assert got == rule and why in reason


def test_a_block_under_the_owners_own_allow_is_dead_and_refused(lg):
    rules = ["@@||x.example^$important", "||ads.x.example^", "||x.example.net^"]
    assert localrules.problems(rules, lg) == [
        ("||ads.x.example^", "your own allow of x.example covers it, so the block would do nothing")
    ]
    assert localrules.problems(["||rdx2.lgtvsdp.com^", "||zz.amagi.tv^"], lg) == []  # single names


@pytest.mark.parametrize(
    "name", ["*.ads.example", "192.0.2.7", "printer.lan", "localhost", "a b.example", ""]
)
def test_a_name_a_site_rule_cannot_hold_is_refused_in_plain_words(name):
    with pytest.raises(ValueError, match="site rule takes"):
        localrules.host_of(name)
    assert localrules.host_of(" Ads.Example. ") == "ads.example"


def test_an_allow_of_a_whole_tracking_domain_needs_force_and_a_single_name_does_not(lg):
    assert localrules.unblocks("alphonso.tv", lg) == ["ACR"] and localrules.needs_force("alphonso.tv", lg)
    # lgtvcommon.com is LG's own zone, and LG's ad and telemetry hosts sit under it
    assert localrules.unblocks("lgtvcommon.com", lg) == ["LG ads", "LG telemetry"]
    assert (
        localrules.plain_categories(["LG ads", "LG telemetry"], lg) == "LG advertising and LG usage reporting"
    )
    assert localrules.needs_force("lgtvcommon.com", lg)
    assert localrules.unblocks("ibs.lgappstv.com", lg) == ["LG ads"]
    assert not localrules.needs_force("ibs.lgappstv.com", lg)  # one host: D28's undo, no --force
    assert localrules.unblocks("ads.example", lg) == [] and not localrules.needs_force("ads.example", lg)


# ---- the plan --------------------------------------------------------------------------------------------
def old_rules(lg, s) -> list[str]:
    """The custom rules as `desired` composed them before site rules existed: the profile's, then the
    machine's that pass the lint."""
    rules = lg.adguard_rules(s.gw_ip, s.tv_ip)
    return rules + [r for r in autoblock.admissible(s.auto_rules, lg)[0] if r not in rules]


def test_without_a_site_rules_file_the_plan_is_byte_identical(lg, site):
    """The owner's gateway has no LOCAL_RULES file: its plan, and so its AdGuardHome.yaml, must be what
    it was before this change, with and without machine rules, and the same for a file of comments."""
    Path(site.auto_rules).write_text(f"{autoblock.HEADER}\n! note\n||tracker.example^\n")
    stock = {"schema_version": 34, "user_rules": ["||old.example^"]}
    before = dataclasses.replace(adguardcfg.desired(lg, site), user_rules=tuple(old_rules(lg, site)))
    assert not os.path.exists(site.local_rules)
    now = adguardcfg.desired(lg, site)
    assert now == before
    assert adguardcfg.dump_yaml(adguardcfg.plan(stock, now)) == adguardcfg.dump_yaml(
        adguardcfg.plan(stock, before)
    )
    os.makedirs(os.path.dirname(site.local_rules))
    Path(site.local_rules).write_text(localrules.HEADER + "\n! nothing yet\n\n")
    assert adguardcfg.desired(lg, site) == before
    assert adguardcfg.rule_groups(lg, site)["local"] == []


def test_the_plan_lists_the_profile_then_the_owner_then_the_machine(lg, site):
    """The golden order: generated rules, the profile's file, the site rules, the machine's rules; a rule
    an earlier group holds is not repeated, and a refused site rule never reaches AdGuard."""
    os.makedirs(os.path.dirname(site.local_rules))
    Path(site.local_rules).write_text(
        "\n".join(
            [
                localrules.HEADER,
                "! 2026-10-26 tvgw allow: the store's sale banner",
                "@@||ibs.lgappstv.com^$important",
                "||alphonso.tv^",  # the profile has it already
                "||snu.lge.com^",  # a hand edit the lint refuses
                "||voice.example^",
            ]
        )
        + "\n"
    )
    Path(site.auto_rules).write_text(f"{autoblock.HEADER}\n||voice.example^\n||tracker.example^\n")
    groups = adguardcfg.rule_groups(lg, site)
    assert groups["profile"] == lg.adguard_rules(site.gw_ip, site.tv_ip)
    assert groups["local"] == ["@@||ibs.lgappstv.com^$important", "||voice.example^"]
    assert groups["machine"] == ["||tracker.example^"]
    rules = list(adguardcfg.desired(lg, site).user_rules)
    assert rules == groups["profile"] + groups["local"] + groups["machine"]
    generated = [f"@@||{h}^$important" for h in lg.must_allow]
    assert rules[: len(generated)] == generated
    # (listguard) the profile's LG ads block carries $important; the owner's allow, carrying it too, outranks it
    assert rules.index("||ibs.lgappstv.com^$important") < rules.index("@@||ibs.lgappstv.com^$important")


def test_an_allow_lifts_a_list_block_in_the_plan_with_the_modifier_that_outranks_it(lg, site):
    """A list's `$important` block loses only to an exception carrying `$important` itself, which is the
    form an allow takes; the plan writes it into AdGuard's user_rules after the profile's block."""
    os.makedirs(os.path.dirname(site.local_rules))
    Path(site.local_rules).write_text("@@||ads.example^$important\n")
    planned = adguardcfg.plan({"schema_version": 34}, adguardcfg.desired(lg, site))
    assert "@@||ads.example^$important" in planned["user_rules"]
    back = yaml.safe_load(adguardcfg.dump_yaml(planned))
    assert back["user_rules"][-1] == "@@||ads.example^$important"


def test_an_unreadable_site_rules_file_stops_the_plan(lg, site, monkeypatch):
    """Planning without the owner's allows would block again what the owner let through."""

    def denied(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(localrules, "read_text", denied)
    with pytest.raises(PermissionError):
        adguardcfg.desired(lg, site)
    # the analyst's pack (a reader) shows the rest of the rules instead of failing
    assert analyst.rules_in_place(lg, site) == old_rules(lg, site)


def test_a_local_block_stays_when_the_machine_reverts_its_own_copy(lg, site):
    os.makedirs(os.path.dirname(site.local_rules))
    Path(site.local_rules).write_text("||tracker.example^\n")
    autoblock.add_rule(site.auto_rules, "||tracker.example^", "2026-10-26 03:50 2026-10-25: tracker.example")
    assert adguardcfg.rule_groups(lg, site)["local"] == ["||tracker.example^"]
    assert adguardcfg.rule_groups(lg, site)["machine"] == []  # held once, by the owner
    assert autoblock.remove_rule(site.auto_rules, "||tracker.example^")
    assert "||tracker.example^" in adguardcfg.desired(lg, site).user_rules


def test_the_diff_shows_the_owners_rules_as_their_own_group(lg, site, tmp_path, monkeypatch, capsys):
    os.makedirs(os.path.dirname(site.local_rules))
    Path(site.local_rules).write_text("@@||ads.example^$important\n")
    before = dataclasses.replace(site, local_rules=str(tmp_path / "none.rules"))
    current = adguardcfg.plan({"schema_version": 34}, adguardcfg.desired(lg, before))
    yml = tmp_path / "AdGuardHome.yaml"
    yml.write_text(adguardcfg.dump_yaml(current))
    conf = tmp_path / "tvgw.conf"
    conf.write_text(
        f"STATE_DIR={site.state_dir}\nDB_PATH={site.db_path}\nAUTO_RULES={site.auto_rules}\n"
        f"LOCAL_RULES={site.local_rules}\nTV_MAC={site.tv_mac}\nTV_NAME={site.tv_name}\n"
    )
    real = cli.config.load

    def load(path, **kw):
        return real(path, adguard_yaml=str(yml), **kw)

    monkeypatch.setattr(cli.config, "load", load)
    assert cli.main(["--conf", str(conf), "adguard", "diff"]) == 1
    out = capsys.readouterr().out
    assert "user_rules by source:" in out
    assert f"  your site rules ({site.local_rules}):\n    + @@||ads.example^$important" in out
    assert "the profile (" not in out  # nothing of the profile's changed
    yml.write_text(adguardcfg.dump_yaml(adguardcfg.plan(current, adguardcfg.desired(lg, site))))
    assert cli.main(["--conf", str(conf), "adguard", "diff"]) == 0
    assert "user_rules by source" not in capsys.readouterr().out


@pytest.mark.parametrize("which", ["local_rules", "auto_rules"])
def test_adguard_names_the_rules_file_it_could_not_read(lg, site, tmp_path, monkeypatch, which):
    """An unreadable rules file stops `tvgw adguard` before anything is planned, and the message names the
    file that failed, the owner's or the machine's, not always the site rules."""
    path = getattr(site, which)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(
        f"STATE_DIR={site.state_dir}\nDB_PATH={site.db_path}\nAUTO_RULES={site.auto_rules}\n"
        f"LOCAL_RULES={site.local_rules}\nTV_MAC={site.tv_mac}\nTV_NAME={site.tv_name}\n"
    )

    def denied(prof, s):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(adguardcfg, "desired", denied)
    with pytest.raises(SystemExit) as stop:
        cli.main(["--conf", str(conf), "adguard", "diff"])
    assert str(stop.value) == f"tvgw adguard: cannot read {path}: Permission denied; nothing was planned"


# ---- the commands ---------------------------------------------------------------------------------------
def test_allow_writes_a_dated_rule_applies_and_says_how_to_undo(lg, site):
    apply = Applies(site, lg)
    done = localrules.allow(site, lg, "Ads.Example", "the weather app's sign-in", apply_fn=apply, now=NOW)
    assert done.code == localrules.OK
    assert done.lines[-1] == "tvgw allow: to undo it: sudo tvgw unallow ads.example"
    assert text(site) == (
        f"{localrules.HEADER}\n! 2026-10-26 tvgw allow: the weather app's sign-in\n@@||ads.example^$important\n"
    )
    assert stat.S_IMODE(os.stat(site.local_rules).st_mode) == 0o640
    assert apply.seen and "@@||ads.example^$important" in apply.seen[-1]
    assert spool(site) == [[f"{NOW:.0f}", "owner", "allow", "ads.example"]]
    again = localrules.allow(site, lg, "ads.example", apply_fn=apply, now=NOW)
    assert again.code == 0 and "already allowed by your rules" in again.lines[-1]
    assert len(apply.seen) == 1  # nothing to apply


def test_an_allow_of_a_whole_tracking_domain_says_what_it_unblocks_and_takes_force(lg, site):
    apply = Applies(site, lg)
    done = localrules.allow(site, lg, "alphonso.tv", apply_fn=apply, now=NOW)
    assert done.code == localrules.REFUSED and not os.path.exists(site.local_rules) and not apply.seen
    assert done.lines == [
        "tvgw allow: this lets alphonso.tv and every name under it through for the TV, which the profile files"
        " under viewing trackers (ACR)",
        "tvgw allow: alphonso.tv is a whole domain of known tracking; nothing changed.",
        "tvgw allow: to allow it anyway: sudo tvgw allow alphonso.tv --force",
    ]
    forced = localrules.allow(site, lg, "alphonso.tv", force=True, apply_fn=apply, now=NOW)
    assert forced.code == 0 and forced.lines[0] == done.lines[0]
    assert "! 2026-10-26 tvgw allow --force: by the owner\n@@||alphonso.tv^$important" in text(site)
    # one host of a tracking zone: said, and taken without --force
    single = localrules.allow(site, lg, "ibs.lgappstv.com", apply_fn=apply, now=NOW)
    assert single.code == 0 and single.lines[0] == (
        "tvgw allow: this lets ibs.lgappstv.com and every name under it through for the TV, which the profile"
        " files under LG advertising"
    )
    assert "tvgw allow ibs.lgappstv.com: by the owner" not in text(site)
    assert "! 2026-10-26 tvgw allow: by the owner\n@@||ibs.lgappstv.com^$important" in text(site)


def test_a_refused_block_changes_nothing(lg, site):
    apply = Applies(site, lg)
    done = localrules.block(site, lg, "snu.lge.com", apply_fn=apply, now=NOW)
    assert done.code == localrules.REFUSED and not apply.seen and not os.path.exists(site.local_rules)
    assert done.lines == [
        "tvgw block: refused: snu.lge.com is kept reachable on purpose: firmware updates (security fixes);"
        " nothing changed"
    ]
    assert spool(site) == []


def test_block_and_allow_replace_each_other_and_the_un_commands_take_them_out(lg, site):
    apply = Applies(site, lg)
    assert localrules.block(site, lg, "voice.example", "never asked for", apply_fn=apply, now=NOW).code == 0
    assert localrules.block(site, lg, "ads.voice.example", apply_fn=apply, now=NOW).code == 0
    done = localrules.allow(site, lg, "voice.example", apply_fn=apply, now=NOW)
    assert done.code == 0
    assert done.lines[:2] == [
        "tvgw allow: your block of voice.example is gone",
        "tvgw allow: your block of ads.voice.example is gone",
    ]
    assert [e.line for e in localrules.entries(site.local_rules)] == ["@@||voice.example^$important"]
    done = localrules.block(site, lg, "voice.example", apply_fn=apply, now=NOW)
    assert done.code == 0 and done.lines[0] == "tvgw block: your allow of voice.example is gone"
    assert [e.line for e in localrules.entries(site.local_rules)] == ["||voice.example^"]
    assert localrules.remove(site, lg, "voice.example", localrules.ALLOW, apply_fn=apply).lines == [
        "tvgw unallow: your rules have no allow of voice.example; nothing changed"
    ]
    gone = localrules.remove(site, lg, "voice.example", localrules.BLOCK, apply_fn=apply, now=NOW)
    assert gone.code == 0 and "is no longer blocked by your rules" in gone.lines[0]
    assert text(site) == localrules.HEADER + "\n"
    assert [f[2:] for f in spool(site)] == [
        ["block", "voice.example"],
        ["block", "ads.voice.example"],
        ["allow", "voice.example"],
        ["block", "voice.example"],
        ["unblock", "voice.example"],
    ]
    missing = localrules.remove(site, lg, "other.example", localrules.BLOCK, apply_fn=apply)
    assert (
        missing.lines[-1]
        == "tvgw unblock: if the lists block it, sudo tvgw allow other.example lets it through"
    )


@pytest.mark.parametrize(
    ("fail", "code", "said"),
    [
        (adguardcfg.Deferred("deferred: upstream down (...); AdGuard Home was not restarted and nothing changed"),
         localrules.DEFERRED, "tvgw allow: deferred: upstream down"),
        (RuntimeError("AdGuard Home rejected the planned file"), localrules.REFUSED,
         "tvgw allow: AdGuard Home did not take the change (AdGuard Home rejected the planned file)"),
    ],
)  # fmt: skip
def test_an_apply_that_is_deferred_or_fails_leaves_both_files_as_they_were(lg, site, fail, code, said):
    os.makedirs(os.path.dirname(site.local_rules))
    Path(site.local_rules).write_text("! mine\n||voice.example^\n")
    autoblock.add_rule(site.auto_rules, "||x.ads.example^", "2026-10-26 03:50 2026-10-25: x.ads.example")
    machine = Path(site.auto_rules).read_text()
    done = localrules.allow(site, lg, "ads.example", apply_fn=Applies(site, lg, fail), now=NOW)
    assert done.code == code and done.lines[-1].startswith(said)
    assert done.lines[-1].endswith("your rules are as they were")
    assert text(site) == "! mine\n||voice.example^\n" and Path(site.auto_rules).read_text() == machine
    assert spool(site) == []


def test_an_allow_takes_the_machines_block_under_it_out_for_the_hourly_check_to_record(lg, site):
    autoblock.add_rule(site.auto_rules, "||x.ads.example^", "2026-10-26 03:50 2026-10-25: x.ads.example")
    typed = "||y.ads.example^$dnstype=HTTPS|SVCB"  # withholds records only: the allow lifts it too
    autoblock.add_rule(site.auto_rules, typed, "2026-10-26 03:50 2026-10-25: y.ads.example")
    autoblock.add_rule(site.auto_rules, "||tracker.example^", "2026-10-26 03:50 2026-10-25: tracker.example")
    apply = Applies(site, lg)
    done = localrules.allow(site, lg, "ads.example", apply_fn=apply, now=NOW)
    assert done.code == 0
    for rule in ("||x.ads.example^", typed):
        assert (
            f"tvgw allow: the gateway's own rule {rule} is out too; the hourly check records it as"
            " undone by you" in done.lines
        )
        assert rule not in apply.seen[-1]
    assert autoblock.read_rules(site.auto_rules) == ["||tracker.example^"]


def test_the_commands_wait_for_the_autonomys_lock_and_give_up_with_nothing_changed(lg, site):
    import fcntl

    fd = os.open(os.path.join(site.state_dir, autoblock.LOCK_NAME), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        slept = []
        done = localrules.allow(
            site, lg, "ads.example", apply_fn=Applies(site, lg), wait=0.0, sleep=slept.append, now=NOW
        )
    finally:
        os.close(fd)
    assert done.code == localrules.REFUSED and "changing rules right now; nothing changed" in done.lines[0]
    assert not os.path.exists(site.local_rules)


def test_the_cli_needs_root_and_lists_the_owners_rules(lg, site, tmp_path, monkeypatch, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(
        f"STATE_DIR={site.state_dir}\nDB_PATH={site.db_path}\nAUTO_RULES={site.auto_rules}\n"
        f"LOCAL_RULES={site.local_rules}\n"
    )
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert cli.main(["--conf", str(conf), "allow", "ads.example"]) == 1
    assert capsys.readouterr().out == (
        "tvgw allow: it changes AdGuard Home's rules; run it with sudo: sudo tvgw allow ads.example\n"
    )
    assert cli.main(["--conf", str(conf), "rules", "--local"]) == 0
    assert "No site rules:" in capsys.readouterr().out
    apply = Applies(site, lg)
    localrules.allow(site, lg, "ads.example", "sign-in", apply_fn=apply, now=NOW)
    with open(site.local_rules, "a", encoding="utf-8") as fh:
        fh.write("||snu.lge.com^\n")  # a hand edit the plan leaves out
    assert cli.main(["--conf", str(conf), "rules", "--local"]) == 0
    out = capsys.readouterr().out.splitlines()
    # (rule use) with no store yet the counts are dashes; tests/unit/test_rulestats.py holds the counts
    assert " ".join(out[0].split()) == "kind name 7 days 30 days names last decided written"
    assert out[1].split()[:2] == ["allow", "ads.example"] and "2026-10-26 tvgw allow: sign-in" in out[1]
    assert out[2].split()[:2] == ["block", "snu.lge.com"] and "not applied: snu.lge.com is kept" in out[2]
    assert out[-1] == "The gateway has no record yet, so the counts are not known."
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    calls = []
    monkeypatch.setattr(
        localrules,
        "block",
        lambda s, p, name, reason: calls.append((name, reason)) or localrules.Outcome(0, ["ok"]),
    )
    assert cli.main(["--conf", str(conf), "block", "voice.example", "--reason", "why"]) == 0
    assert calls == [("voice.example", "why")]


# ---- the machine, the record and forget -------------------------------------------------------------
def test_the_gate_and_the_vetting_refuse_a_name_the_owner_allowed(lg):
    p = {"kind": "block", "name": "x.ads.example", "rule": "||x.ads.example^", "vetted": "ok", "risk": "low"}
    shape = {"days_seen": 5, "conns": 3, "median_down": 10, "total_down": 30}
    assert autoblock.gate(p, shape, [], 0) == "ok"
    assert autoblock.gate(p, shape, [], 0, owner_allows=("ads.example",)) == autoblock.OWNER_ALLOWED
    # a rule that acts on an allowed name under another heading is caught by its target too
    other = {**p, "name": "x.other.example", "rule": "||ads.example^"}
    assert autoblock.gate(other, shape, [], 0, owner_allows=("ads.example",)) == autoblock.OWNER_ALLOWED
    result = {
        "proposals": [{"kind": "block", "name": "x.ads.example", "rule": "||x.ads.example^", "risk": "low"}]
    }
    (vetted,) = analyst.vet(result, lg, lg.adguard_rules(), ("ads.example",))["proposals"]
    assert vetted["vetted"] == "refused: allowed by the owner (local.rules)"
    (plain,) = analyst.vet(result, lg, lg.adguard_rules())["proposals"]
    assert plain["vetted"] == "ok"


def test_an_autonomous_block_under_an_owners_allow_is_never_applied(lg, tmp_path, monkeypatch):
    """The analyst's run reads the owner's file at the gate: the block is refused with the owner named,
    and nothing reaches the machine's file or AdGuard."""
    from test_autoblock import DAY, FakeClient, agree, block, message, proposals, steady_sampler, store

    key = tmp_path / "k"
    key.write_text("sk-ant-test\n")
    key.chmod(0o600)
    local = tmp_path / "local.rules"
    local.write_text("@@||tracker.example^$important\n")
    s = Settings(
        tv_mac="b4:b2:91:aa:bb:cc",
        state_dir=str(tmp_path),
        db_path=store(tmp_path),
        reports_dir=str(tmp_path / "reports"),
        auto_rules=str(tmp_path / "auto.rules"),
        local_rules=str(local),
        analyst_apply="auto",
    )
    applies = []
    hooks = {
        "call": agree,
        "apply": lambda: applies.append(1),
        "sampler": steady_sampler(),
        "sleep": lambda x: None,
    }
    client = FakeClient(message(proposals(block("tracker.example"))))
    assert analyst.run(s, lg, DAY, make_client=lambda k: client, key_path=str(key), hooks=hooks) == 0
    md = (tmp_path / "reports" / "proposals" / f"{DAY}.md").read_text()
    assert "- Applied: no: allowed by the owner (local.rules)" in md
    assert applies == [] and autoblock.read_rules(s.auto_rules) == []
    record = json.loads((tmp_path / "reports" / "proposals" / f"{DAY}.json").read_text())
    assert [x["outcome"] for x in record["autonomous"]] == ["refused"]
    # the model was shown the owner's allow among the rules in place
    sent = client.calls[0]["messages"][0]["content"]
    assert "@@||tracker.example^$important" in json.dumps(sent)


def test_an_owner_spool_line_is_an_owner_rule_change(site):
    row = ledger._spool_row(["1793020000", "owner", "allow", "ads.example"], site, None)
    assert (row.kind, row.subject, row.detail, row.source) == (
        "owner_rule_change",
        "ads.example",
        {"action": "allow"},
        "owner",
    )
    assert ledger.KINDS["owner_rule_change"][:2] == ("A", 1)
    assert "owner_rule_change" in ledger.GROUPS["Gateway"]
    assert ledger._spool_row(["1793020000", "owner", "rewrite", "ads.example"], site, None) is None


def test_the_ingest_loads_the_owners_line_once(site):
    localrules_spool = ledger.spool_path(site)
    ledger.append_spool(localrules_spool, ["owner", "block", "voice.example"], NOW)
    conn = db.connect(site.db_path)
    from tvgw import ingest

    n = ledger.load_spool(conn, site, ingest._tail, lambda m: None)
    conn.commit()
    assert n == 1
    assert conn.execute("SELECT kind, subject, effect_class FROM changes").fetchall() == [
        ("owner_rule_change", "voice.example", "A")
    ]
    conn.close()


def test_the_full_briefs_rule_changes_lists_an_allow_once_adguard_holds_it(lg, site, tmp_path):
    """The design's acceptance: after `tvgw allow`, the hourly ingest reads the rule from AdGuard's YAML
    like any other, and the full brief's Rule changes section lists that line and nothing else new."""
    import io

    from tvgw import ingest, queries

    site = dataclasses.replace(site, adguard_yaml=str(tmp_path / "AdGuardHome.yaml"))

    def apply():  # what `tvgw adguard apply` leaves in AdGuard's file
        planned = adguardcfg.plan({"schema_version": 34}, adguardcfg.desired(lg, site))
        Path(site.adguard_yaml).write_text(adguardcfg.dump_yaml(planned), encoding="utf-8")

    conn = db.connect(site.db_path)
    apply()  # the profile's rules alone, an hour before
    ingest.ingest_rules(conn, *ingest.current_rules(site), now=NOW - 3600)
    done = localrules.allow(site, lg, "ads.example", reason="the news app", apply_fn=apply, now=NOW)
    assert done.code == localrules.OK
    ingest.ingest_rules(conn, *ingest.current_rules(site), now=NOW + 60)
    conn.commit()
    o = queries.window_report(conn, NOW, NOW + 3600, lg, now=NOW + 3600)
    assert [(c["kind"], c["text"]) for c in o["rule_changes"]] == [("adguard", "@@||ads.example^$important")]
    out = io.StringIO()
    cli.render_brief(o, out)
    brief = out.getvalue()
    assert "\nRule changes:" in brief
    assert brief.split("\nRule changes:")[1].count("@@||ads.example^$important") == 1
    conn.close()


def test_forget_keeps_the_site_rules_wherever_they_live(site):
    os.makedirs(os.path.dirname(site.local_rules))
    Path(site.local_rules).write_text("||voice.example^\n")
    steps = forget.plan_files(site, live=set())
    (step,) = [x for x in steps if x.what == site.local_rules]
    assert step.action == "keep" and step.why == forget.LOCAL_RULES_WHY
    inside = dataclasses.replace(site, local_rules=os.path.join(site.state_dir, "site.rules"))
    Path(inside.local_rules).write_text("||voice.example^\n")
    steps = forget.plan_files(inside, live=set())
    assert [x.action for x in steps if x.what == inside.local_rules] == ["keep"]
    assert not [x for x in steps if x.action == "unclassified"]


def test_an_allow_says_when_it_lifts_a_block_no_list_can_lift(lg, site):
    """(listguard) The profile's red-line blocks carry $important, so no subscribed list lifts them; the
    owner's allow, which carries it too, still does, on purpose, and says so (design decision 68)."""
    apply = Applies(site, lg)
    done = localrules.allow(site, lg, "ibs.lgappstv.com", apply_fn=apply, now=NOW)
    assert done.code == 0
    assert (
        "tvgw allow: the profile keeps ibs.lgappstv.com blocked against a blocklist's plain exception; your own"
        " allow lets it through all the same"
    ) in done.lines
    assert "@@||ibs.lgappstv.com^$important" in apply.seen[-1]
    assert "||ibs.lgappstv.com^$important" in apply.seen[-1]
    plain = localrules.allow(site, lg, "sdk.wurl.dev", apply_fn=apply, now=NOW)
    assert not any("plain exception" in line for line in plain.lines)  # wurl.dev is not held
    assert localrules.held_blocks("x.ibs.lgappstv.com", lg) == ["ibs.lgappstv.com"]
    assert localrules.held_blocks("lgappstv.com", lg) == [
        "ibs.lgappstv.com",
        "ibsstat.lgappstv.com",
        "ad.lgappstv.com",
        "ibis.lgappstv.com",
        "lgshopsvc.lgappstv.com",
    ]


def test_an_allow_of_a_name_a_held_regex_blocks_says_so_too(lg, site):
    """(listguard) The profile's held regex blocks (LG's ad and telemetry hosts under aws-prd.net) are lifted by
    the owner's allow as well, and the message names the rule, since no single name stands for it."""
    nevo = "/^([a-z0-9]+-)?nevoai-iothub-[0-9]+-prod\\.azure-devices\\.net$/$important"
    assert localrules.held_blocks("nevoai-iothub-54-prod.azure-devices.net", lg) == [
        f"the names {nevo} matches"
    ]
    ads = localrules.held_blocks("us-ad-lgsmartad-com.aws-prd.net", lg)
    assert ads == ["the names /^[a-z]{2}-(ad|info)-lgsmartad-com\\.aws-prd\\.net$/$important matches"]
    assert localrules.held_blocks("cdn.example", lg) == []
    done = localrules.allow(site, lg, "us-ad-lgsmartad-com.aws-prd.net", apply_fn=Applies(site, lg), now=NOW)
    assert any(line.startswith("tvgw allow: the profile keeps the names /^") for line in done.lines), (
        done.lines
    )
