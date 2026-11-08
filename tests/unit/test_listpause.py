"""(pause) `tvgw pause`: the shared tracker lists off for a few minutes, back on their own two ways, and the
names they were stopping at the end (design decision 79).

AdGuard Home is its YAML on disk, written by the real `adguardcfg.apply()` with a stand-in for systemctl,
the readiness wait, the binary's own check and the restart guard; its query log is a file written the way
v0.107.79 appends it, and check_host a function that answers as its handler does. The timer is a recorder
of the systemd-run it would start. The store is a real one. All times are on 2026-10-26, America/Chicago,
around `NOW` (10:00), as conftest pins them."""

from __future__ import annotations

import dataclasses
import json
import os
import random
import sys
from datetime import datetime
from pathlib import Path

import pytest
from conftest import NOW

from tvgw import (
    adguardcfg,
    aghinstall,
    autoblock,
    cli,
    db,
    doctor,
    ledger,
    listpause,
    plain,
    profile,
    queries,
    verify,
)
from tvgw.config import Settings

TV = "10.10.10.17"
BCRYPT = "$2a$10$" + "x" * 53
LG_LIST = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_72.txt"  # HaGeZi LG webOS
PRO = "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt"  # HaGeZi Pro
DOH = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh.txt"  # the bypass list
MIN = 60
DAY = 86400


def iso(t: float) -> str:
    """A time as AdGuard writes it: nanoseconds and the local offset."""
    d = datetime.fromtimestamp(t).astimezone()
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond:06d}123" + d.strftime("%z")[:3] + ":00"


def log_line(t: float, name: str, blocked: bool = False, rule: str | None = None, fid: int = 0) -> str:
    """One line of AdGuard's query-log file for the TV: answered with no rule, or refused by `rule`."""
    result: dict = {"Reason": 3 if blocked else 0}
    if rule is not None:
        result["Rules"] = [{"Text": rule, **({"FilterListID": fid} if fid else {})}]
    if blocked:
        result["IsFiltered"] = True
    record = {"T": iso(t), "QH": name, "QT": "A", "QC": "IN", "CP": "", "IP": TV, "Result": result}
    return json.dumps({**record, "Elapsed": 120000}) + "\n"


@dataclasses.dataclass
class Site:
    s: Settings
    prof: profile.Profile
    cfg: dict
    admin: Path
    applied: list = dataclasses.field(default_factory=list)  # the `paused` of every apply asked for
    armed: list = dataclasses.field(default_factory=list)  # (seconds, argv) of every timer set
    disarmed: int = 0
    calls: list = dataclasses.field(default_factory=list)  # systemctl, as the apply called it
    guard: object = None  # what the restart guard does: None passes, an exception is raised

    def ids(self) -> dict[str, int]:
        return {f["url"]: f["id"] for f in self.cfg["filters"]}

    def yaml(self) -> dict:
        return adguardcfg.load_yaml(self.s.adguard_yaml)

    def enabled(self) -> dict[str, bool]:
        return {f["url"]: f["enabled"] for f in self.yaml()["filters"]}

    def apply(self, paused: tuple[str, ...]) -> list[str]:
        """The real apply of the plan, with stand-ins for what touches the gateway."""
        self.applied.append(paused)

        def guard() -> None:
            if self.guard is not None:
                raise self.guard

        return adguardcfg.apply(
            self.s.adguard_yaml,
            adguardcfg.desired(self.prof, self.s, paused),
            control=lambda *a: self.calls.append(a),
            ready=lambda: True,
            check=lambda path: (True, ""),
            guard=guard,
        )

    def arm(self, seconds: int, argv: list[str]) -> str | None:
        self.armed.append((seconds, argv))
        return None

    def disarm(self) -> None:
        self.disarmed += 1

    def hooks(self, **kw) -> dict:
        return {"apply_fn": self.apply, "disarm_fn": self.disarm, "sleep": lambda s: None, **kw}

    def row(self) -> listpause.Pause | None:
        return listpause.read(self.s.db_path)

    def spool(self) -> list[ledger.Change]:
        path = ledger.spool_path(self.s)
        if not os.path.exists(path):
            return []
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        return [ledger._spool_row(line.split("\t"), self.s, None) for line in lines]


@pytest.fixture
def site(tmp_path, lg) -> Site:
    (tmp_path / "data").mkdir()
    (tmp_path / "state").mkdir()
    s = Settings(
        tv_ip=TV,
        tv_mac="b4:b2:91:aa:bb:cc",
        tv_name="lgcx",
        adguard_yaml=str(tmp_path / "AdGuardHome.yaml"),
        adguard_querylog=str(tmp_path / "data" / "querylog.json"),
        local_rules=str(tmp_path / "local.rules"),
        auto_rules=str(tmp_path / "auto.rules"),
        db_path=str(tmp_path / "tvgw.db"),
        state_dir=str(tmp_path / "state"),
    )
    users = {"users": [{"name": "admin", "password": BCRYPT}], "schema_version": 34}
    cfg = adguardcfg.plan(users, adguardcfg.desired(lg, s, ()))
    Path(s.adguard_yaml).write_text(adguardcfg.dump_yaml(cfg), encoding="utf-8")
    admin = tmp_path / "adguard-admin"
    aghinstall.write_admin(str(admin), "admin", "secret")
    db.connect(s.db_path).close()
    return Site(s, lg, cfg, admin)


def clock_at(t: float):
    now = [t]
    return now, (lambda: now[0])


# ---- the profile marks the bypass list ------------------------------------------------------------------
@pytest.mark.parametrize("name", profile.bundled_names())
def test_every_bundled_profile_keeps_its_doh_list_out_of_a_pause(name):
    """The list of encrypted-DNS servers closes a way around the filter, so every bundled profile marks it
    `role = "bypass"` by its entry, and a pause takes only the others: the shared tracker lists."""
    p = profile.load(name)
    roles = {url: p.filter_role(url) for _, url in p.adguard_filters}
    assert roles[DOH] == profile.BYPASS
    assert [u for u, r in roles.items() if r == profile.TRACKING] == [u for _, u in p.tracking_filters()]
    assert DOH not in {u for _, u in p.tracking_filters()} and p.tracking_filters()


def test_a_filters_role_defaults_to_tracking_and_a_wrong_one_is_refused():
    def load(entry: dict) -> profile.Profile:
        return profile.from_dict({"adguard": {"filters": [entry]}})

    plain_entry = {"name": "x", "url": "https://x.example/l"}
    assert load(plain_entry).tracking_filters() == (("x", "https://x.example/l"),)
    assert load({**plain_entry, "role": "bypass"}).tracking_filters() == ()
    with pytest.raises(ValueError, match="the role of 'x' is not one of"):
        load({**plain_entry, "role": "doh"})
    # a misspelt key would leave a bypass list pausable: refused, as an unknown key of other tables is
    with pytest.raises(ValueError, match="unknown key 'rol'"):
        load({**plain_entry, "rol": "bypass"})


# ---- the plan with and without a pause ------------------------------------------------------------------
def _flat_without_enabled(cfg: dict) -> dict:
    return {
        k: v
        for k, v in adguardcfg._flatten(cfg).items()
        if not (k.startswith("filters.") and k.endswith(".enabled"))
    }


@pytest.mark.parametrize("name", profile.bundled_names())
@pytest.mark.parametrize("seed", range(4))
def test_a_pause_changes_nothing_but_the_tracker_lists_enabled(name, seed):
    """For every bundled profile, over a stock config and configs holding lists and clients of their own in
    random order: the plan with the pause differs from the plan without it only in `filters.N.enabled`,
    exactly the tracker lists are off, and the bypass list and every list not the profile's stay as they
    were. Whatever `paused` names, the bypass list is dropped from it."""
    rng = random.Random(seed)
    p = profile.load(name)
    s = Settings(db_path="/nonexistent/tvgw.db")
    current: dict = {"schema_version": 34, "filters": [], "clients": {"persistent": []}}
    for i in range(rng.randint(0, 3)):
        current["filters"].append(
            {
                "enabled": rng.random() < 0.5,
                "url": f"https://own{i}.example/l",
                "name": f"own {i}",
                "id": 900 + i,
            }
        )
    if rng.random() < 0.5:
        current["filters"].append({"enabled": False, "url": DOH, "name": "theirs", "id": 77})
    rng.shuffle(current["filters"])
    every = tuple(u for _, u in p.adguard_filters)  # the bypass list too: desired must drop it
    off, on = adguardcfg.desired(p, s, every), adguardcfg.desired(p, s, ())
    assert DOH not in off.paused and set(off.paused) == {u for _, u in p.tracking_filters()}
    paused, plain_plan = adguardcfg.plan(current, off), adguardcfg.plan(current, on)
    assert _flat_without_enabled(paused) == _flat_without_enabled(plain_plan)
    states = {f["url"]: f["enabled"] for f in paused["filters"]}
    assert {u for u, e in states.items() if u in dict(map(reversed, p.adguard_filters))} == set(every)
    assert all(not states[u] for _, u in p.tracking_filters())
    assert states[DOH] is True
    others = {f["url"]: f["enabled"] for f in current["filters"] if f["url"] not in every}
    assert {u: states[u] for u in others} == others
    assert all(f["enabled"] for f in plain_plan["filters"] if f["url"] in every)


def test_desired_reads_a_pause_in_force_from_the_store_and_none_past_its_end(site, lg):
    conn = db.connect(site.s.db_path)
    p = listpause.Pause(NOW - 5 * MIN, NOW + 5 * MIN, 10, lg.tracking_filters())
    db.set_meta(conn, listpause.META_KEY, p.as_json())
    conn.commit()
    assert set(adguardcfg.desired(lg, site.s).paused) == {LG_LIST, PRO}
    for later in (
        dataclasses.replace(p, end=NOW),  # its end has come: a reboot's first apply renders no pause
        dataclasses.replace(p, ended=NOW - MIN, how="early"),
        dataclasses.replace(p, lists=(("HaGeZi DoH/VPN bypass (DoH only)", DOH),)),  # a hand edit
    ):
        db.set_meta(conn, listpause.META_KEY, later.as_json())
        conn.commit()
        assert adguardcfg.desired(lg, site.s).paused == ()
    db.set_meta(conn, listpause.META_KEY, "{not json")
    conn.commit()
    assert adguardcfg.desired(lg, site.s).paused == ()  # a row it cannot read is no pause: lists on
    conn.close()


# ---- starting ---------------------------------------------------------------------------------------------
def test_a_pause_switches_the_tracker_lists_off_sets_its_timer_and_records_its_start(site, lg):
    _, clock = clock_at(NOW)
    done = listpause.start(site.s, lg, 10, argv=["tvgw", "pause", "--end", "--timer"], arm_fn=site.arm,
                           clock=clock, **site.hooks())  # fmt: skip
    assert done.code == listpause.OK
    assert site.armed == [(600, ["tvgw", "pause", "--end", "--timer"])]
    assert site.applied == [(LG_LIST, PRO)]
    assert site.enabled() == {LG_LIST: False, DOH: True, PRO: False}
    assert ("stop", "AdGuardHome") in site.calls and ("start", "AdGuardHome") in site.calls
    row = site.row()
    assert (row.start, row.end, row.minutes, row.urls, row.ended) == (
        NOW,
        NOW + 600,
        10,
        (LG_LIST, PRO),
        None,
    )
    (line,) = site.spool()
    assert (line.kind, line.subject, line.t, line.t_end) == ("owner_pause", "start", NOW, NOW + 600)
    assert line.detail == {"action": "start", "minutes": 10, "until": NOW + 600}
    assert done.lines[0].startswith("tvgw pause: the shared blocklists are off until 10:10 (HaGeZi LG webOS")


def test_a_second_pause_is_refused_with_the_end_time(site, lg):
    _, clock = clock_at(NOW)
    assert listpause.start(site.s, lg, 10, arm_fn=site.arm, clock=clock, **site.hooks()).code == listpause.OK
    done = listpause.start(site.s, lg, 5, arm_fn=site.arm, clock=clock, **site.hooks())
    assert done.code == listpause.REFUSED and "already paused until 10:10" in done.lines[0]
    assert len(site.armed) == 1 and len(site.applied) == 1  # nothing else was set or applied
    overdue = listpause.start(site.s, lg, 5, arm_fn=site.arm, clock=lambda: NOW + 11 * MIN, **site.hooks())
    assert (
        overdue.code == listpause.REFUSED
        and "should have ended at 10:10 is still in force" in overdue.lines[0]
    )


@pytest.mark.parametrize("minutes", [0, -1, 61])
def test_a_pause_is_one_to_sixty_minutes(site, lg, minutes):
    with pytest.raises(ValueError, match="1 to 60"):
        listpause.start(site.s, lg, minutes, arm_fn=site.arm, **site.hooks())


def test_with_the_upstreams_down_it_says_deferred_exits_3_and_pauses_nothing(site, lg):
    site.guard = adguardcfg.Deferred("deferred: upstream down (a fresh lookup SERVFAILs)")
    before = Path(site.s.adguard_yaml).read_text(encoding="utf-8")
    done = listpause.start(site.s, lg, 10, arm_fn=site.arm, **site.hooks())
    assert done.code == listpause.DEFERRED == cli.DEFERRED_EXIT
    assert done.lines == [
        "tvgw pause: deferred: upstream down (a fresh lookup SERVFAILs); nothing was paused"
    ]
    assert Path(site.s.adguard_yaml).read_text(encoding="utf-8") == before and site.calls == []
    assert site.row() is None and site.disarmed == 1 and site.spool() == []


def test_a_change_adguard_refuses_puts_the_last_pause_back_and_stops_the_timer(site, lg):
    old = listpause.Pause(NOW - DAY, NOW - DAY + 600, 10, lg.tracking_filters(), NOW - DAY + 600, "timer")
    conn = db.connect(site.s.db_path)
    db.set_meta(conn, listpause.META_KEY, old.as_json())
    conn.commit()
    conn.close()

    def broken(paused):
        raise RuntimeError("AdGuard Home rejected the planned config")

    done = listpause.start(site.s, lg, 10, arm_fn=site.arm, **{**site.hooks(), "apply_fn": broken})
    assert done.code == listpause.REFUSED and "nothing was paused" in done.lines[0]
    assert site.row() == old and site.disarmed == 1


def test_without_its_timer_a_pause_does_not_start(site, lg):
    done = listpause.start(
        site.s, lg, 10, arm_fn=lambda sec, argv: "Failed to connect to bus", **site.hooks()
    )
    assert done.code == listpause.REFUSED and "could not set the timer" in done.lines[0]
    assert "Failed to connect to bus" in done.lines[0]
    assert site.applied == [] and site.row() is None


def test_a_start_waits_for_the_hourly_check_and_then_refuses(site, lg):
    with autoblock.exclusive(site.s.state_dir) as free:
        assert free
        done = listpause.start(site.s, lg, 10, arm_fn=site.arm, wait=0, **site.hooks())
    assert done.code == listpause.REFUSED and "hourly check or the analyst" in done.lines[0]
    assert site.applied == [] and site.armed == []


def test_a_profile_without_a_tracker_list_has_nothing_to_pause(site, lg):
    bare = dataclasses.replace(lg, adguard_filters=((("DoH", DOH)),), filter_roles={DOH: profile.BYPASS})
    done = listpause.start(site.s, bare, 10, arm_fn=site.arm, **site.hooks())
    assert done.code == listpause.REFUSED and "no shared tracker list" in done.lines[0]


# ---- ending -----------------------------------------------------------------------------------------------
def started(site: Site, lg, minutes: int = 10, at: float = NOW) -> None:
    assert listpause.start(site.s, lg, minutes, arm_fn=site.arm, clock=lambda: at, **site.hooks()).code == 0


def test_an_early_end_brings_the_lists_back_stops_the_timer_and_records_how(site, lg):
    started(site, lg)
    done = listpause.end(site.s, lg, listpause.EARLY, clock=lambda: NOW + 4 * MIN, **site.hooks())
    assert done.code == listpause.OK and site.applied[-1] == ()
    assert site.enabled() == {LG_LIST: True, DOH: True, PRO: True}
    assert site.disarmed == 1
    row = site.row()
    assert (row.ended, row.how) == (NOW + 4 * MIN, "early") and not row.in_force(NOW + 5 * MIN)
    end_line = site.spool()[-1]
    assert (end_line.subject, end_line.detail) == ("end", {"action": "end", "minutes": 4, "ended": "early"})
    assert done.lines == [
        "tvgw pause --end: the shared blocklists are back on: paused 4 minutes, from 10:00 to 10:04, ended by"
        " sudo tvgw pause --end"
    ]
    again = listpause.end(site.s, lg, listpause.EARLY, **site.hooks())
    assert again.code == 0 and again.lines == ["tvgw pause --end: no pause is in force; nothing changed"]


def test_an_end_the_upstreams_hold_back_leaves_the_pause_in_force_to_be_tried_again(site, lg):
    started(site, lg)
    site.guard = adguardcfg.Deferred("deferred: upstream down")
    done = listpause.end(site.s, lg, listpause.EARLY, clock=lambda: NOW + MIN, **site.hooks())
    assert done.code == listpause.DEFERRED and "stay off for now" in done.lines[0]
    assert site.row().ended is None and site.enabled()[PRO] is False and len(site.spool()) == 1


def test_an_end_does_not_wait_for_ever_on_the_hourly_check(site, lg):
    """Protection does not wait on a judgement: past its wait, an end goes ahead without the lock."""
    started(site, lg)
    with autoblock.exclusive(site.s.state_dir) as free:
        assert free
        done = listpause.end(site.s, lg, listpause.EARLY, clock=lambda: NOW + MIN, wait=0, **site.hooks())
    assert done.code == listpause.OK and "without waiting for it" in done.lines[0]
    assert site.enabled()[PRO] is True


def test_an_apply_that_finds_adguards_lock_held_is_tried_again(site, lg):
    started(site, lg)
    tries = []

    def busy_twice(paused):
        tries.append(paused)
        if len(tries) < 3:
            raise adguardcfg.Busy("another tvgw adguard apply is running")
        return site.apply(paused)

    done = listpause.end(site.s, lg, listpause.EARLY, **{**site.hooks(), "apply_fn": busy_twice})
    assert done.code == listpause.OK and len(tries) == 3


def test_the_timer_ends_the_pause_and_a_stray_early_timer_ends_nothing(site, lg):
    started(site, lg)
    early = listpause.end(site.s, lg, listpause.TIMER, clock=lambda: NOW + 2 * MIN, **site.hooks())
    assert early.code == 0 and "ends at 10:10, not now" in early.lines[0] and site.row().ended is None
    done = listpause.end(site.s, lg, listpause.TIMER, clock=lambda: NOW + 10 * MIN, **site.hooks())
    assert done.code == 0 and site.row().how == "timer" and site.disarmed == 0  # the fired timer is gone


def test_the_timer_tries_again_while_the_upstreams_are_down_then_gives_way_to_the_hourly_check(site, lg):
    started(site, lg)
    now, clock = clock_at(NOW + 10 * MIN)
    said, slept = [], []

    def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds
        if len(slept) == 2:  # the outage is over after two waits
            site.guard = None

    site.guard = adguardcfg.Deferred("deferred: upstream down")
    done = listpause.end_by_timer(site.s, lg, said.append, clock=clock, sleep=sleep,
                                  apply_fn=site.apply, disarm_fn=site.disarm)  # fmt: skip
    assert done.code == 0 and slept == [listpause.RETRY_EVERY] * 2 and site.row().how == "timer"
    assert said.count("tvgw pause --end: trying again in 5 minutes") == 2


def test_the_timer_gives_way_to_the_hourly_check_after_a_long_outage(site, lg):
    started(site, lg)
    now, clock = clock_at(NOW + 10 * MIN)
    slept = []

    def sleep(seconds):
        slept.append(seconds)
        now[0] += seconds

    site.guard = adguardcfg.Deferred("deferred: upstream down")
    done = listpause.end_by_timer(site.s, lg, lambda line: None, clock=clock, sleep=sleep,
                                  apply_fn=site.apply, disarm_fn=site.disarm)  # fmt: skip
    assert done.code == listpause.DEFERRED and len(slept) == listpause.RETRY_FOR // listpause.RETRY_EVERY
    assert site.row().ended is None  # the hourly check's fallback ends it once the upstreams answer


def test_the_hourly_check_ends_a_pause_past_its_end_and_nothing_else(site, lg):
    assert listpause.fallback(site.s, lg) is None  # no pause at all
    started(site, lg)
    assert listpause.fallback(site.s, lg, clock=lambda: NOW + 9 * MIN, **site.hooks()) is None  # in force
    done = listpause.fallback(site.s, lg, clock=lambda: NOW + 70 * MIN, **site.hooks())
    assert done.code == 0 and site.row().how == "fallback" and site.enabled()[PRO] is True
    assert "ended by the hourly check" in done.lines[0]
    assert listpause.fallback(site.s, lg, clock=lambda: NOW + 80 * MIN, **site.hooks()) is None  # over


def test_the_hourly_check_runs_the_fallback_before_it_judges(site, lg, monkeypatch, capsys):
    calls = []

    def fallback(s, prof):
        calls.append("fallback")
        return listpause.Outcome(
            listpause.REFUSED, ["tvgw pause --end: AdGuard Home did not take the change"]
        )

    monkeypatch.setattr(listpause, "fallback", fallback)
    monkeypatch.setattr(cli, "_shadow", lambda *a, **k: None)
    from tvgw import analyst

    monkeypatch.setattr(analyst, "check", lambda conn, s, prof, watch: calls.append("check") or [])
    conf = Path(site.s.state_dir) / "tvgw.conf"
    conf.write_text(f"STATE_DIR={site.s.state_dir}\nDB_PATH={site.s.db_path}\n", encoding="utf-8")
    assert cli.main(["--conf", str(conf), "autoblock", "check"]) == 1  # the failed end is said by the exit
    assert calls == ["fallback", "check"]
    assert "AdGuard Home did not take the change" in capsys.readouterr().out


# ---- the ledger -------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "fields",
    [
        ["owner", "pause", "start", "10"],  # no planned end
        ["owner", "pause", "start", "ten", "1793027400"],
        ["owner", "pause", "start", "10", "1"],  # an end before the start
        ["owner", "pause", "end", "10", "because"],
        ["owner", "pause", "resume", "10", "timer"],
    ],
)
def test_a_damaged_pause_line_is_unread_never_stored_half_right(site, fields):
    assert ledger._spool_row([str(NOW), *fields], site.s, None) is None


def test_a_pause_is_class_a_and_a_gateway_change():
    assert ledger.KINDS["owner_pause"][:2] == ("A", 1) and "owner_pause" in ledger.GROUPS["Gateway"]
    assert set(listpause.ENDED_BY) == set(ledger.PAUSE_ENDS)


# ---- verify -----------------------------------------------------------------------------------------------
SENTINELS = {
    "h4g3z1-native-lgwebos.web.app": ["0.0.0.0"],
    "h4g3z1-doh.web.app": ["0.0.0.0"],
    "h4g3z1-pro.web.app": ["0.0.0.0"],
}


def test_a_paused_list_is_a_warning_until_the_pause_is_over_never_a_failure(lg):
    answers = {
        **SENTINELS,
        "h4g3z1-native-lgwebos.web.app": ["198.51.100.7"],
        "h4g3z1-pro.web.app": ["198.51.100.8"],
    }
    p = listpause.Pause(NOW - MIN, NOW + 9 * MIN, 10, lg.tracking_filters())
    c = verify.sentinel_check(lg, answers.get, p, NOW)
    assert c.ok and c.warn and c.detail.startswith("paused until 10:09: h4g3z1-native-lgwebos.web.app->")
    late = verify.sentinel_check(lg, answers.get, p, NOW + 30 * MIN)
    assert late.ok and late.warn and "should have ended at 10:09 is still in force" in late.detail
    over = verify.sentinel_check(lg, answers.get, dataclasses.replace(p, ended=NOW, how="early"), NOW + MIN)
    assert not over.ok and over.detail.startswith("list not in force:")
    assert not verify.sentinel_check(lg, answers.get, None, NOW).ok
    # the bypass list is never paused: its sentinel fails during a pause as at any other time
    doh_off = {**answers, "h4g3z1-doh.web.app": ["198.51.100.9"]}
    c = verify.sentinel_check(lg, doh_off.get, p, NOW)
    assert (
        not c.ok and c.detail.startswith("list not in force: h4g3z1-doh.web.app->") and "pro" not in c.detail
    )
    # a pause in force whose lists still answer 0.0.0.0 (its apply not yet run) is simply in force
    assert verify.sentinel_check(lg, SENTINELS.get, p, NOW) == verify.sentinel_check(lg, SENTINELS.get)


def test_verify_reads_the_pause_from_the_store_meta(site, lg):
    started(site, lg)
    record = verify.store_meta(site.s.db_path)
    assert verify.pause_of(record) == site.row()


def test_the_doctor_explains_a_pause_and_offers_the_end_of_one_past_its_end(site, lg):
    paused = verify.Check(
        "list_sentinels", True, "paused until 10:09: h4g3z1-pro.web.app->x; 2 in force", True
    )
    plan = doctor.plan_for(paused, site.s, lg, None, {})
    assert plan.fixes == [] and "sudo tvgw pause" in plan.notes[0]
    late = verify.Check(
        "list_sentinels", True, "the pause that should have ended at 10:09 is still in force", True
    )
    assert doctor.plan_for(late, site.s, lg, None, {}).fixes == [doctor.PAUSE_END_FIX]


# ---- the brief --------------------------------------------------------------------------------------------
def write_changes(conn, rows: list[ledger.Change]) -> None:
    ledger.write(conn, rows)
    conn.commit()


def pause_rows(start: float, minutes: int, ended: float | None, how: str = "timer") -> list[ledger.Change]:
    rows = [ledger._spool_row([str(start), "owner", "pause", "start", str(minutes), str(start + minutes * 60)],
                              Settings(), None)]  # fmt: skip
    if ended is not None:
        lasted = str(round((ended - start) / 60))
        rows.append(ledger._spool_row([str(ended), "owner", "pause", "end", lasted, how], Settings(), None))
    return rows


def test_the_brief_lists_each_pause_and_the_plain_new_line_says_it(site, lg):
    conn = db.connect(site.s.db_path)
    write_changes(
        conn, pause_rows(NOW - 2 * 3600, 10, NOW - 2 * 3600 + 600) + pause_rows(NOW - 600, 30, None)
    )
    found = queries.pauses(conn, NOW - 86400, NOW)
    assert [(x["minutes"], x["ended"], x["end"] is None) for x in found] == [
        (10, "timer", False),
        (30, None, True),
    ]
    o = queries.window_report(conn, NOW - 86400, NOW, lg, now=NOW)
    rows = [(r["kind"], r["text"]) for r in o["rule_changes"]]
    assert rows == [
        ("pause", "shared blocklists paused (10 min, ended by its timer)"),
        ("pause", "shared blocklists paused (30 min asked; no end recorded yet)"),
    ]
    new = plain._new(o, None)
    assert new == (
        "New: the shared blocklists were paused for 10 minutes at 08:00; the shared blocklists were paused"
        " for 30 minutes at 09:50."
    )
    conn.close()


def test_a_name_the_tv_reached_only_during_a_pause_is_no_list_update(site, lg):
    """The list red line: a list blocking, after a pause, a name the TV resolved only while the lists were
    off is no update of the list. Without the pause's window it would be one (the rule broken on purpose)."""
    conn = db.connect(site.s.db_path)
    start = NOW - 3 * 3600
    row = (
        "INSERT INTO dns(t, qname, qtype, answers, blocked, reason, rule, filter_id) VALUES (?,?,?,?,?,?,?,?)"
    )
    answered = ("A", "A:198.51.100.7", 0, "NotFilteredNotFound", None, None)
    conn.executemany(
        row,
        [
            (start + 60, "ads.example.net", *answered),  # first seen during the pause, blocked after it
            (start + 900, "ads.example.net", "A", None, 1, "FilteredBlockList", "||ads.example.net^", 48),
            (
                start - 3600,
                "pixel.example.net",
                "A",
                None,
                1,
                "FilteredBlockList",
                "||pixel.example.net^",
                48,
            ),
            (start + 120, "pixel.example.net", *answered),  # blocked before the pause, answered during it
        ],
    )
    conn.commit()
    assert [x["name"] for x in queries.list_newly_blocked(conn, start + 600, NOW)] == ["ads.example.net"]
    assert [x["name"] for x in queries.list_newly_allowed(conn, start, start + 600)] == ["pixel.example.net"]
    write_changes(conn, pause_rows(start, 10, start + 600))
    assert queries.list_newly_blocked(conn, start + 600, NOW) == []
    assert queries.list_newly_allowed(conn, start, start + 600) == []
    conn.close()


# ---- the answer at the end --------------------------------------------------------------------------------
def answers(site: Site, blocked: dict[str, str]):
    """check_host as AdGuard answers it: a name in `blocked` by `||name^` from the list at that URL, or
    from the custom rules (list id 0) for "custom"."""
    asked = []

    def check(base, name, client, user, password):
        asked.append((name, client, user, password))
        if name in blocked:
            fid = 0 if blocked[name] == "custom" else site.ids()[blocked[name]]
            return {"reason": "FilteredBlackList", "rules": [{"text": f"||{name}^", "filter_list_id": fid}]}
        return {"reason": "NotFilteredNotFound", "rules": []}

    return check, asked


def no_page(*a, **k) -> dict:
    return {"data": [], "oldest": ""}


def ended_pause(lg, start=NOW - 20 * MIN, end=NOW - 10 * MIN) -> listpause.Pause:
    return listpause.Pause(start, start + 600, 10, lg.tracking_filters(), end, "timer")


def test_the_report_ranks_what_the_lists_block_again_as_tvgw_refused_does(site, lg):
    """A clock host a list blocks ranks first (the TV needs it), then a name never refused before, then a
    known tracker, whatever the counts; a name the lists do not block, one only a list the pause left on
    or a rule of tvgw's blocks now (the pause never lifted those), and a lookup outside the pause, are not
    in it. The first gets the fix line, with its list."""
    p = ended_pause(lg)
    tracker = "tpc.googlesyndication.com"
    lines = [log_line(p.start - 300, tracker, True, f"||{tracker}^", site.ids()[PRO])]  # refused before
    lines += [log_line(p.start + 10 + i, tracker) for i in range(30)]
    lines += [log_line(p.start + 60 + i, "api.example.net") for i in range(5)]
    lines += [log_line(p.start + 120, "eu.lgtvsdp.com"), log_line(p.start + 130, "video.example.com")]
    lines += [log_line(p.start + 140, "doh.example.net"), log_line(p.start + 150, "since.example.net")]
    lines += [log_line(p.ended + 60, "late.example.org")]  # after the lists were back
    Path(site.s.adguard_querylog).write_text("".join(lines), encoding="utf-8")
    check, asked = answers(
        site,
        {
            tracker: PRO,
            "api.example.net": PRO,
            "eu.lgtvsdp.com": LG_LIST,
            "late.example.org": PRO,
            "doh.example.net": DOH,  # the bypass list, which no pause switches off
            "since.example.net": "custom",  # a rule written since: the pause did not lift it
        },
    )
    done = listpause.report(site.s, lg, p, now=NOW, check=check, page=no_page, admin=str(site.admin))
    assert done.code == listpause.NAMED
    assert {a[0] for a in asked} == {
        tracker,
        "api.example.net",
        "eu.lgtvsdp.com",
        "video.example.com",
        "doh.example.net",
        "since.example.net",
    }
    assert all(a[1:] == (TV, "admin", "secret") for a in asked)
    assert done.lines[0] == (
        "During the pause, from 09:40 to 09:50, the TV reached 3 names the shared blocklists block again now,"
        " the likeliest cause first:"
    )
    assert [line.split(",")[0].strip() for line in done.lines[1:4]] == [
        "eu.lgtvsdp.com",
        "api.example.net",
        tracker,
    ]
    assert "HaGeZi LG webOS" in done.lines[1] and "a known tracker" in done.lines[3]
    assert done.lines[4] == (
        "If the app worked during the pause, the likely cause is eu.lgtvsdp.com (HaGeZi LG webOS): sudo tvgw"
        " allow eu.lgtvsdp.com"
    )


def test_the_fix_line_names_the_list_and_the_allow(site, lg):
    p = ended_pause(lg)
    Path(site.s.adguard_querylog).write_text(
        "".join(log_line(p.start + 60 + i, "api.example.net") for i in range(3)), encoding="utf-8"
    )
    check, _ = answers(site, {"api.example.net": PRO})
    done = listpause.report(site.s, lg, p, now=NOW, check=check, page=no_page, admin=str(site.admin))
    assert done.lines == [
        "During the pause, from 09:40 to 09:50, the TV reached 1 name the shared blocklists block again now:",
        "  api.example.net, looked up 3 times: HaGeZi Pro. Kind: other services.",
        "If the app worked during the pause, the likely cause is api.example.net (HaGeZi Pro): sudo tvgw allow"
        " api.example.net",
        "If the app failed during the pause too, the shared lists were not the cause: run sudo tvgw refused"
        " right after it fails.",
    ]


def test_with_nothing_the_lists_block_reached_they_were_not_the_cause(site, lg):
    p = ended_pause(lg)
    Path(site.s.adguard_querylog).write_text(log_line(p.start + 60, "video.example.com"), encoding="utf-8")
    check, _ = answers(site, {})
    done = listpause.report(site.s, lg, p, now=NOW, check=check, page=no_page, admin=str(site.admin))
    assert done.code == listpause.NOTHING and done.lines == [listpause.NOT_THE_CAUSE]
    assert listpause.NOT_THE_CAUSE == (
        "The TV reached nothing the shared lists block during the pause, so they were not the cause: run sudo"
        " tvgw refused right after the app fails."
    )
    Path(site.s.adguard_querylog).write_text("", encoding="utf-8")
    quiet = listpause.report(site.s, lg, p, now=NOW, check=check, page=no_page, admin=str(site.admin))
    assert quiet.code == listpause.NOTHING and "looked up nothing during the pause" in quiet.lines[0]


def test_at_most_200_names_are_asked_the_ones_not_answered_before_first(site, lg):
    p = ended_pause(lg)
    lines = [log_line(p.start - 100, "old0.example.net")]  # answered before the pause: asked last
    lines += [log_line(p.start + 1 + i / 1000, f"old{i % 2}.example.net") for i in range(50)]
    lines += [log_line(p.start + 60 + i / 1000, f"n{i}.example.net") for i in range(250)]
    Path(site.s.adguard_querylog).write_text("".join(lines), encoding="utf-8")
    check, asked = answers(site, {})
    done = listpause.report(site.s, lg, p, now=NOW, check=check, page=no_page, admin=str(site.admin))
    assert len(asked) == listpause.ASKED == 200
    assert asked[0][0] == "old1.example.net" and "old0.example.net" not in {a[0] for a in asked}
    assert "52 more names the TV looked up during the pause were not asked about" in done.lines[-1]


def test_without_adguards_password_it_says_how_to_see_the_names(site, lg):
    p = ended_pause(lg)
    Path(site.s.adguard_querylog).write_text(log_line(p.start + 60, "api.example.net"), encoding="utf-8")
    done = listpause.report(
        site.s, lg, p, now=NOW, check=answers(site, {})[0], admin=str(site.admin) + ".none"
    )
    assert done.code == listpause.UNREAD
    assert "the TV looked up 1 name during the pause" in done.lines[0]
    assert done.lines[1].endswith("sudo tvgw pause --report")


def test_adguard_stopping_part_way_gives_no_half_ranking(site, lg):
    p = ended_pause(lg)
    Path(site.s.adguard_querylog).write_text(
        "".join(log_line(p.start + 60 + i, f"n{i}.example.net") for i in range(3)), encoding="utf-8"
    )

    def check(base, name, *a):
        if name == "n1.example.net":
            raise aghinstall.AskError("AdGuard Home did not answer")
        return {
            "reason": "FilteredBlackList",
            "rules": [{"text": f"||{name}^", "filter_list_id": site.ids()[PRO]}],
        }

    done = listpause.report(site.s, lg, p, now=NOW, check=check, page=no_page, admin=str(site.admin))
    assert done.code == listpause.UNREAD and "stopped answering" in done.lines[0]


# ---- what it says before it asks --------------------------------------------------------------------------
def test_it_says_what_stays_and_what_goes_and_the_general_profile_warns_of_every_tracker(lg):
    s = Settings()
    words = listpause.describe(lg, s, 10, NOW)
    assert words[0] == (
        "For 10 minutes, the gateway stops using these shared blocklists for the TV: HaGeZi LG webOS and"
        " HaGeZi Pro."
    )
    kept = "\n".join(words)
    for stays in (
        "the blocks of this TV's profile",
        "your own rules",
        "the names the TV must always reach",
        "the filter on the TV maker's file service",
        "HaGeZi DoH/VPN bypass (DoH only)",
        "QUIC and LG's ad ports stay refused",
        "separation from your home network",
    ):
        assert stays in kept, stays
    assert words[-1].startswith("At 10:10 the lists come back on their own")
    general = listpause.describe(profile.load("generic-tv"), dataclasses.replace(s, block_quic="no"), 5, NOW)
    text = "\n".join(general)
    assert "the blocks of this TV's profile" not in text and "QUIC" not in text and "file service" not in text
    assert (
        "This TV's profile blocks no names of its own, so while the lists are off the TV can reach every"
        " tracker they know, its maker's included." in general
    )


# ---- the command ------------------------------------------------------------------------------------------
@pytest.fixture
def conf(site, tmp_path, monkeypatch) -> str:
    path = tmp_path / "tvgw.conf"
    path.write_text(
        f"STATE_DIR={site.s.state_dir}\nDB_PATH={site.s.db_path}\nLOCAL_RULES={site.s.local_rules}\n"
        f"AUTO_RULES={site.s.auto_rules}\nTV_MAC={site.s.tv_mac}\nTV_NAME={site.s.tv_name}\n",
        encoding="utf-8",
    )
    real = cli.config.load
    monkeypatch.setattr(cli.config, "load", lambda p, **kw: real(p, adguard_yaml=site.s.adguard_yaml, **kw))
    return str(path)


def test_status_needs_no_root_and_says_whether_a_pause_is_in_force(site, lg, conf, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(listpause, "armed", lambda: None)
    assert cli.main(["--conf", conf, "pause", "--status"]) == 0
    assert capsys.readouterr().out == "No pause is in force: the shared blocklists are on.\n"
    started(site, lg, at=NOW - 3 * MIN)
    assert cli.main(["--conf", conf, "pause", "--status"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert (
        out[0]
        == "The shared blocklists are paused until 10:07, 7 minutes from now: HaGeZi LG webOS and HaGeZi Pro."
    )
    assert (
        listpause.status(site.s, NOW, timer=lambda: False)
        .lines[-1]
        .startswith("The timer that ends the pause is not")
    )
    assert listpause.status(site.s, NOW + 8 * MIN).code == listpause.REFUSED  # past its end, not over


@pytest.mark.parametrize(
    ("argv", "code"),
    [
        (["pause", "0"], 2),
        (["pause", "61"], 2),
        (["pause", "--end", "5"], 2),
        (["pause", "--status", "--yes"], 2),
        (["pause", "--timer"], 2),
    ],
)
def test_minutes_and_options_out_of_place_are_usage_errors(conf, monkeypatch, argv, code):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert cli.main(["--conf", conf, *argv]) == code


def test_anyone_but_root_is_sent_to_sudo_and_nothing_changes(site, conf, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert cli.main(["--conf", conf, "pause"]) == 1
    assert capsys.readouterr().out.splitlines()[-1] == "  sudo tvgw pause 10"
    assert site.row() is None


def test_without_a_terminal_or_yes_it_asks_and_changes_nothing(site, conf, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert cli.main(["--conf", conf, "pause", "15"]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("For 15 minutes, the gateway stops using")
    assert out[-1] == "tvgw pause: nothing changed; add --yes to pause without the question"
    assert site.row() is None


def test_the_command_pauses_with_yes_and_hands_the_timer_its_settings(site, lg, conf, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    got = {}

    def start(s, prof, minutes, argv):
        got.update(minutes=minutes, argv=argv)
        return listpause.Outcome(0, ["tvgw pause: the shared blocklists are off until 10:20"])

    monkeypatch.setattr(listpause, "start", start)
    assert cli.main(["--conf", conf, "--db", site.s.db_path, "pause", "20", "--yes"]) == 0
    assert got["minutes"] == 20
    assert got["argv"][1:] == ["--conf", conf, "--db", site.s.db_path, "pause", "--end", "--timer"]


def test_adguard_diff_names_a_pause_in_force_instead_of_drift(site, lg, conf, monkeypatch, capsys):
    started(site, lg, at=NOW - MIN)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert cli.main(["--conf", conf, "adguard", "diff"]) == 0
    out = capsys.readouterr().out
    assert "filters." not in out
    assert (
        "A pause is in force until 10:09: the shared blocklists HaGeZi LG webOS and HaGeZi Pro are off" in out
    )
    # past its end and not over: the plan renders no pause, so the lists are drift, and the note says why
    monkeypatch.setattr(listpause.time, "time", lambda: NOW + 30 * MIN)
    assert cli.main(["--conf", conf, "adguard", "diff"]) == 1
    out = capsys.readouterr().out
    assert "enabled: False -> True" in out
    assert "should have ended at 10:09 and is not over: sudo tvgw pause --end ends it now." in out
