"""(depth) `tvgw status`: three lines about now from /run/tvgw/status.txt alone, and its exit tiers.

It reads no settings file and no store, so it works for any account and with a settings file nobody may
read; 0 means nothing to do, 1 a gateway matter (`sudo tvgw doctor`), 2 something on the TV.
"""

import os
import re
import stat

import pytest
from conftest import NOW

from tvgw import cli, config, status, verify

T = int(NOW) - 240  # the last check, four minutes before now


def lines(text):
    return status.lines(text, NOW)


def test_a_check_that_held_says_nothing_needs_attention():
    shown, code = lines(f"ok {T} 34\n")
    assert code == 0
    assert shown == [
        "tvgw: the protection held at 09:56 (34 checks passed).",
        "The checks run every 10 minutes; this one is 4 minutes old.",
        "Nothing needs your attention.",
    ]


def test_failed_checks_on_the_gateway_send_the_reader_to_the_doctor():
    shown, code = lines(f"fail {T} services disk\n")
    assert code == 1
    assert shown[0] == "tvgw: 2 checks failed at 09:56: services, disk."
    assert shown[2] == "Run: sudo tvgw doctor"
    assert lines(f"fail {T} services\n")[0][0] == "tvgw: 1 check failed at 09:56: services."


def test_a_check_whose_fix_is_on_the_tv_is_the_act_tier():
    shown, code = lines(f"fail {T} tv_paths\n")
    assert code == 2
    assert shown[2] == "On the TV: switch Wi-Fi and Wi-Fi Direct off and forget every saved network."
    both, code = lines(f"fail {T} tv_paths services\n")
    assert code == 2 and both[2].endswith(". Then run: sudo tvgw doctor")


def test_a_check_that_stopped_running_is_a_gateway_matter():
    old = int(NOW) - 2 * 3600
    shown, code = lines(f"ok {old} 34\n")
    assert code == 1
    assert shown[1] == "The checks have not run for 2 hours: they may have stopped."
    assert shown[2] == "Run: sudo tvgw doctor"
    days = int(NOW) - 3 * 86400
    assert lines(f"ok {days} 34\n")[0][0].startswith("tvgw: the protection held at 2026-10-23 ")
    assert lines(f"ok {days} 34\n")[0][1] == "The checks have not run for 3 days: they may have stopped."
    assert lines(f"ok {int(NOW) + 60} 34\n")[0][1].endswith(
        "this one is under a minute old."
    )  # clock set back


def test_no_status_file_yet_and_one_that_cannot_be_parsed():
    shown, code = lines(None)
    assert code == 1 and shown[0] == "tvgw: no check has run since this computer started."
    assert len(shown) == 3
    for bad in ("", "ok", "ok nope 3", "fail 123", "ok 123 3 extra", "fail 123 Services", "maybe 1 2"):
        shown, code = lines(bad)
        assert code == 1 and shown[0] == "tvgw: the last check's verdict could not be read.", bad


def test_the_lines_carry_check_names_and_times_only():
    """The status file is readable by every account and holds no detail; neither does what status prints."""
    first = lines(f"fail {T} services tv_route\n")[0][0]
    assert re.fullmatch(r"tvgw: 2 checks failed at \d\d:\d\d: services, tv_route\.", first)
    assert all(not re.search(r"\d+\.\d+\.\d+", line) for line in lines(f"ok {T} 34\n")[0])


def test_main_reads_the_status_file_verify_writes(status_file):
    verify.write_status(verify.Result(checks=[verify.Check("ruleset", True)], t=float(T)), str(status_file))
    out = []
    assert status.main(str(status_file), now=NOW, out=out.append) == 0
    assert out[0] == "tvgw: the protection held at 09:56 (1 checks passed)."
    assert status.main(str(status_file.parent / "absent.txt"), now=NOW, out=out.append) == 1


def test_an_unreadable_status_file_is_said_not_raised(tmp_path):
    d = tmp_path / "status.txt"
    d.mkdir()  # reading a directory raises IsADirectoryError, an OSError
    out = []
    assert status.main(str(d), now=NOW, out=out.append) == 1
    assert out[0] == "tvgw: the last check's verdict could not be read."


def test_tvgw_status_reads_no_settings_file(tmp_path, monkeypatch, capsys, status_file):
    """With a settings file this account may not read, every other command stops; status answers."""
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_IP=10.10.10.17\n")
    monkeypatch.setattr(config, "load", lambda *a, **k: pytest.fail("status must not load the settings"))
    status_file.write_text(f"fail {T} services\n")
    assert cli.main(["--conf", str(conf), "status"]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("tvgw: 1 check failed at ") and out[2] == "Run: sudo tvgw doctor"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
@pytest.mark.parametrize(
    ("line", "code"),
    [("ok {t} 34", 0), ("fail {t} services", 1), ("fail {t} tv_paths", 2), (None, 1)],
)
def test_status_gives_each_exit_tier_with_a_settings_file_it_may_not_read(
    tmp_path, capsys, status_file, line, code
):
    """The settings file really unreadable (mode 0), not a stand-in: every exit tier still comes."""
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_IP=10.10.10.17\n")
    if line is None:
        status_file.unlink(missing_ok=True)
    else:
        status_file.write_text(line.format(t=T) + "\n")
    conf.chmod(0)
    try:
        got = cli.main(["--conf", str(conf), "status"])
    finally:
        conf.chmod(stat.S_IRUSR | stat.S_IWUSR)
    out = capsys.readouterr().out.splitlines()
    assert got == code and len(out) == 3, out


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_a_settings_file_outside_adm_is_one_sentence_not_a_traceback(tmp_path, capsys):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("TV_IP=10.10.10.17\n")
    conf.chmod(0)
    try:
        with pytest.raises(SystemExit) as e:
            cli.main(["--conf", str(conf), "brief"])
    finally:
        conf.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert e.value.code == cli.NEEDS_SETTINGS
    assert cli.NEEDS_SETTINGS == (
        "tvgw: this needs the gateway's settings: run it with sudo, or ask the computer's owner to add your"
        " account to the adm group"
    )


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_a_store_outside_adm_is_the_same_sentence(tmp_path):
    from tvgw import db

    store = tmp_path / "tvgw.db"
    db.connect(str(store)).close()
    store.chmod(0)
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"DB_PATH={store}\n")
    try:
        with pytest.raises(SystemExit) as e:
            cli.main(["--conf", str(conf), "size"])
    finally:
        store.chmod(stat.S_IRUSR | stat.S_IWUSR)
    assert e.value.code == cli.NEEDS_SETTINGS


def test_a_permission_error_inside_a_command_is_the_same_sentence(tmp_path, monkeypatch):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("")

    def denied(a, s, prof):
        raise PermissionError(13, "Permission denied", "/var/lib/tvgw/onscreen.log")

    monkeypatch.setattr(cli, "cmd_size", denied)
    parser = cli.build_parser
    monkeypatch.setattr(cli, "build_parser", lambda: _with(parser(), "size", denied))
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as e:
        cli.main(["--conf", str(conf), "size"])
    assert e.value.code == cli.NEEDS_SETTINGS
    # root may read every file of the gateway's: its PermissionError is something else, and is raised
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    with pytest.raises(PermissionError, match="Permission denied"):
        cli.main(["--conf", str(conf), "size"])


def _with(parser, name, fn):
    for action in parser._subparsers._group_actions:  # the subcommand's handler, replaced
        if name in action.choices:
            action.choices[name].set_defaults(fn=fn)
    return parser


def test_what_is_counting_follows_the_three_lines_and_changes_no_exit_tier(status_file):
    """(counting) The file `tvgw verify --record` leaves beside the status: one plain line for each count
    that runs, after the three; keys, states and times only, so nothing in it can name the household."""
    from tvgw import counting

    status_file.write_text(f"fail {T} services\n", encoding="utf-8")
    counting_file = status_file.parent / counting.FILE
    since = T - 3 * 86400
    counting_file.write_text(
        f"ntp counting {since} {since + 14 * 86400}\nprobe off - -\nlive stopped {since} -\n",
        encoding="utf-8",
    )
    out = []
    assert status.main(str(status_file), now=NOW, out=out.append) == 1
    assert out[3:] == [
        "Counting, and refusing nothing until you decide:",
        "  the TV's requests to time servers: since 23 October; its two weeks end on 6 November",
    ]
    counting_file.write_text("garbage\n", encoding="utf-8")
    out = []
    status.main(str(status_file), now=NOW, out=out.append)
    assert len(out) == 3
