"""(updates) What the owner reads about updates: the brief's New and Updates lines, verify's `updates` check
and the doctor's words, `tvgw updates` and its refusals, and install.sh's timer block (design decision 77)."""

import json
import re
import shutil
import subprocess
from dataclasses import replace
from datetime import datetime

import pytest
from conftest import NOW, ROOT, load_tool
from test_plain import measured_day

from tvgw import cli, db, doctor, plain, queries, updates, verify
from tvgw.config import Settings

S = Settings()
DAY = 86400.0
INSTALL = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")


def day_with(updates_section: dict, day: str = "2026-11-04") -> dict:
    o = measured_day()
    o["since"], o["until"] = queries.day_bounds(day)
    o["updates"] = {"runs": [], "running": "0.3.2", "previous": None, **updates_section}
    return o


def at(day: str, hh: int = 3, mm: int = 50) -> float:
    return datetime.fromisoformat(f"{day}T{hh:02d}:{mm:02d}").timestamp()


# ---- the New line -----------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "day, said",
    [
        ("2026-11-02", True),
        ("2026-11-03", False),
        ("2026-11-08", False),
        ("2026-11-09", True),
        ("2026-11-16", True),
    ],
)
def test_a_newer_tvgw_is_news_on_the_day_it_was_first_seen_and_once_a_week_after(day, said):
    o = day_with({"latest": "0.4.0", "latest_seen_t": at("2026-11-02", 4, 10)}, day)
    line = plain.plain_brief(o)[4]
    assert ("tvgw 0.4.0 is available" in line) is said, line


@pytest.mark.parametrize("latest", ["0.3.2", "0.3.1", "0.4.0-rc.1", None])
def test_the_same_an_older_or_a_pre_release_is_never_news(latest):
    o = day_with({"latest": latest, "latest_seen_t": at("2026-11-04")})
    assert "available" not in plain.plain_brief(o)[4]


def test_security_updates_are_news_after_a_week_of_waiting_then_weekly():
    since = at("2026-10-26", 9)
    for day, said in (
        ("2026-10-26", False),  # the day they were first seen: not a week yet
        ("2026-11-01", False),
        ("2026-11-02", True),
        ("2026-11-05", False),
        ("2026-11-09", True),
    ):
        o = day_with({"security": 2, "security_since": since}, day)
        line = plain.plain_brief(o)[4]
        want = "the gateway's system has security updates waiting since Monday 26 October"
        assert (want in line) is said, (day, line)
    assert (
        "waiting"
        not in plain.plain_brief(day_with({"security": 0, "security_since": since}, "2026-11-02"))[4]
    )


# ---- the Updates line ---------------------------------------------------------------------------------------
def run(t, **kw) -> dict:
    return {"t": t, "trigger": "night", "mode": "all", **kw}


def notes(o) -> list[str]:
    return [line for line in plain.plain_brief(o) if line.startswith("  Updates:")]


def test_a_night_that_installed_is_one_line_and_never_the_action():
    o = day_with(
        {
            "runs": [
                run(
                    at("2026-11-04", 3, 52),
                    result="installed",
                    system={"outcome": "installed", "count": 12, "security": 4},
                    adguard={"outcome": "installed", "before": "0.107.80", "after": "0.107.81"},
                    verify="held",
                    reboot="done",
                ),
                {"t": at("2026-11-04", 3, 58), "trigger": "reboot", "result": "held", "verify": "held"},
            ]
        }
    )
    assert notes(o) == [
        "  Updates: At 03:52, the gateway installed 12 system updates (4 for security) and AdGuard Home"
        " 0.107.81; its checks held afterwards; it restarted to finish them. At 03:58, after its restart"
        " for an update, the gateway's checks held."
    ]
    assert plain.plain_brief(o)[5] == "  Action: nothing needs your attention."


def test_a_rollback_says_what_was_put_back():
    o = day_with(
        {
            "runs": [
                run(
                    at("2026-11-04"),
                    result="rolled_back",
                    tvgw={
                        "outcome": "rolled_back",
                        "before": "0.3.2",
                        "after": "0.4.0",
                        "why": "verify failed",
                    },
                )
            ]
        }
    )
    assert notes(o) == ["  Updates: At 03:50, tvgw 0.4.0 failed the gateway's checks, so 0.3.2 was put back."]


def test_a_night_that_waited_is_said_once_until_a_night_does_not_wait():
    wait = run(at("2026-11-04"), result="waited", why=updates.NOT_QUIET)
    first = day_with({"runs": [wait], "previous": {"result": "installed"}})
    assert notes(first) == [f"  Updates: At 03:50, the gateway waited: {updates.NOT_QUIET}."]
    again = day_with({"runs": [wait], "previous": {"result": "waited"}})
    assert notes(again) == []
    nothing = day_with({"runs": [run(at("2026-11-04"), result="nothing")]})
    assert notes(nothing) == []


def test_the_brief_carries_the_section_from_the_store(tmp_path, lg):
    conn = db.connect(str(tmp_path / "tvgw.db"))
    a, _ = queries.day_bounds("2026-10-26")
    updates.remember(conn, run(a + 3 * 3600, result="nothing"))
    updates.remember(conn, run(a - 3600, result="waited", why="x"))
    db.set_meta(conn, updates.META_CHECK, json.dumps({"t": a, "ok": True, "latest": "0.4.0", "seen_t": a}))
    conn.commit()
    o = queries.brief(conn, "2026-10-26", lg)
    sec = o["updates"]
    assert [r["t"] for r in sec["runs"]] == [a + 3 * 3600] and sec["previous"]["result"] == "waited"
    assert sec["latest"] == "0.4.0" and sec["running"] == updates.__version__


# ---- verify's check ----------------------------------------------------------------------------------------
def level(s=S, reading=None, check=None, runs=(), dump="", unattended=True, reboot_t=None):
    reading = (
        reading if reading is not None else {"t": NOW, "waiting": 0, "security": 0, "lists_t": NOW - DAY}
    )
    return verify.updates_level(s, reading, check, list(runs), dump, unattended, reboot_t, NOW)


def good_dump(mode: str) -> str:
    from test_updates import dump_of

    return dump_of(updates.apt_conf(mode))


def test_a_current_gateway_is_ok_and_says_how_current():
    assert level() == (verify.OK, "no security update waiting; package lists 24 hours old")


@pytest.mark.parametrize(
    "kw, warns",
    [
        (
            {"reading": {"t": NOW, "security": 2, "since": NOW - 15 * DAY, "lists_t": NOW}},
            "2 security updates waiting",
        ),
        ({"reading": {"t": NOW, "security": 2, "since": NOW - 13 * DAY, "lists_t": NOW}}, None),
        (
            {"reading": {"t": NOW, "security": 0, "lists_t": NOW - 31 * DAY}},
            "package lists are 31.0 days old",
        ),
        ({"reading": {"t": NOW, "security": 0, "lists_t": NOW - 29 * DAY}}, None),
        ({"s": replace(S, update_check="weekly"), "check": {"failures": 4}}, "failed 4 times in a row"),
        ({"s": replace(S, update_check="weekly"), "check": {"failures": 3}}, None),
        ({"check": {"failures": 9}}, None),  # the check is off: its old failures are no finding
    ],
)
def test_the_thresholds_of_the_check(kw, warns):
    found, detail = level(**kw)
    assert found == (verify.WARN if warns else verify.OK), detail
    assert warns is None or warns in detail


@pytest.mark.parametrize(
    "kw, warns",
    [
        ({"unattended": False}, "unattended-upgrades is not installed"),
        ({"dump": ""}, "could not be read"),
        ({"runs": [{"t": NOW - DAY, "result": "rolled_back"}]}, "the last automatic install was rolled back"),
        (
            {"runs": [{"t": NOW - DAY, "result": "failed", "trigger": "reboot"}]},
            "after the gateway's restart failed",
        ),
        ({"runs": [{"t": NOW - 9 * DAY, "result": "rolled_back"}]}, None),
        ({"reboot_t": NOW - 8 * DAY}, "a restart to finish an update has waited 8.0 days"),
        ({"reboot_t": NOW - DAY}, None),
    ],
)
def test_with_installs_on_the_check_reads_their_configuration_and_their_record(kw, warns):
    s = replace(S, update_install="all")
    kw.setdefault("dump", good_dump("all"))
    found, detail = level(s, **kw)
    assert found == (verify.WARN if warns else verify.OK), detail
    assert warns is None or warns in detail


def test_the_check_is_a_warning_whatever_it_finds():
    s = replace(S, update_install="all", update_check="weekly")
    reading = {"t": NOW, "security": 9, "since": NOW - 90 * DAY, "lists_t": NOW - 90 * DAY}
    c = verify.Check(
        "updates", *verify.held("updates", *level(s, reading, {"failures": 9}, unattended=False))
    )
    assert c.ok and c.warn and not c.detail.endswith(verify.HELD)  # never more than a warning, even held
    assert verify.FAIL_AFTER["updates"] == verify.WARN


def test_the_reading_verify_takes_is_stored_by_the_recorded_run(tmp_path):
    conn = db.connect(str(tmp_path / "tvgw.db"))
    r = verify.Result(t=NOW, system={"t": NOW, "waiting": 1, "security": 1, "since": NOW})
    verify.record(conn, r)
    assert json.loads(db.get_meta(conn, updates.META_SYSTEM))["since"] == NOW


# ---- the doctor ------------------------------------------------------------------------------------------
def test_the_doctor_explains_and_installs_nothing(lg):
    c = verify.Check("updates", True, "2 security updates waiting for 20.0 days", warn=True)
    p = doctor.plan_for(c, S, lg, env=None, probed={})
    assert p.fixes == [] and "installs nothing itself" in p.notes[0]
    assert any("sudo tvgw updates --now" in n for n in p.notes)


# ---- tvgw updates ---------------------------------------------------------------------------------------
def test_every_mode_that_writes_needs_root(monkeypatch, capsys, tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    for flag in ("--now", "--check-now", "--scheduled", "--after-reboot", "--configure"):
        assert cli.main(["--conf", str(conf), "updates", flag]) == 2
    assert "run it with sudo" in capsys.readouterr().out


def test_check_now_and_now_refuse_while_the_settings_say_off(monkeypatch, capsys, tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"DB_PATH={tmp_path}/tvgw.db\n")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(updates, "open_url", lambda url, timeout: pytest.fail(f"asked {url}"))
    monkeypatch.setattr(updates, "live_env", lambda *a: pytest.fail("installed"))
    assert cli.main(["--conf", str(conf), "updates", "--check-now"]) == 1
    assert "asks GitHub nothing" in capsys.readouterr().out
    assert cli.main(["--conf", str(conf), "updates", "--now"]) == 1
    assert "UPDATE_INSTALL=off" in capsys.readouterr().out


def test_the_report_needs_no_store_and_prints_three_lines(monkeypatch, capsys, tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"DB_PATH={tmp_path}/none.db\nSTATE_DIR={tmp_path}\n")
    monkeypatch.setattr(updates, "_run", lambda argv, timeout=60, env=None: (127, ""))
    assert cli.main(["--conf", str(conf), "updates"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert [ln.split(":")[0] for ln in lines] == ["tvgw", "AdGuard Home", "System"]
    assert cli.main(["--conf", str(conf), "updates", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tvgw"]["installed"] == updates.__version__ and data["install"] == "off"


def test_the_commands_the_doctor_and_verify_name_exist_in_this_version():
    texts = [*doctor.UPDATES_NOTES, *verify.PLAIN["updates"]]
    found = {m for t in texts for m in load_tool("docgen").COMMAND.findall(t) if m.startswith("sudo tvgw ")}
    assert {"sudo tvgw updates", "sudo tvgw updates --now"} <= found, found
    parser = cli.build_parser()
    for command in found:
        parser.parse_args(command.removeprefix("sudo tvgw ").split())


# ---- install.sh's block ------------------------------------------------------------------------------------
def installer_block(tmp_path, settings: str) -> list[str]:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("install.sh is a bash script")
    (block,) = re.findall(
        r"# \(updates\) The weekly check and the installs.*?\nsystemctl -q enable tvgw-update-boot[^\n]*\n",
        INSTALL,
        re.S,
    )
    fake = tmp_path / "systemctl"
    fake.write_text(f'#!/bin/sh\necho "$*" >>{tmp_path}/calls\n', encoding="utf-8")
    fake.chmod(0o755)
    (tmp_path / "calls").write_text("", encoding="utf-8")
    defaults = next(ln for ln in INSTALL.splitlines() if "${UPDATE_INSTALL:=" in ln)
    script = f"set -euo pipefail\nPATH={tmp_path}:$PATH\n{settings}\n{defaults}\n{block}"
    out = subprocess.run([bash, "-c", script], capture_output=True, text=True, encoding="utf-8")
    assert out.returncode == 0, out.stderr
    return (tmp_path / "calls").read_text(encoding="utf-8").splitlines()


@pytest.mark.parametrize(
    "settings, enabled",
    [
        ("", False),  # an old settings file: no timer, no request, no install
        ("UPDATE_CHECK=off; UPDATE_INSTALL=off", False),
        ("UPDATE_CHECK=weekly", True),
        ("UPDATE_INSTALL=security", True),
        ("UPDATE_INSTALL=all; UPDATE_CHECK=weekly", True),
        ("UPDATE_INSTALL=", False),
    ],
)
def test_the_timer_runs_only_when_a_setting_asks(tmp_path, settings, enabled):
    calls = installer_block(tmp_path, settings)
    timer = "enable --now tvgw-update.timer" if enabled else "disable --now tvgw-update.timer"
    assert calls == [timer, "-q enable tvgw-update-boot.service"]


def test_the_template_keeps_installs_off_and_the_check_on_for_new_installs_and_the_package_cleans_up():
    example = (ROOT / "deploy" / "tvgw.conf.example").read_text(encoding="utf-8")
    assert re.search(r"^UPDATE_INSTALL=off$", example, re.M) and re.search(
        r"^UPDATE_CHECK=weekly$", example, re.M
    )
    postrm = (ROOT / "packaging" / "scripts" / "postrm").read_text(encoding="utf-8")
    assert f"rm -f {updates.APT_CONF}" in postrm and "tvgw-update.timer.d" in postrm
    assert "tvgw updates --configure" in INSTALL
    boot = (ROOT / "deploy" / "systemd" / "tvgw-update-boot.service").read_text(encoding="utf-8")
    assert f"ConditionPathExists=/var/lib/tvgw/{updates.REBOOT_MARKER}" in boot
    assert "tvgw-update" not in " ".join(verify.SERVICES)  # a timer that is off is no outage
