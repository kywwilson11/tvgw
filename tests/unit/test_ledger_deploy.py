"""(ledger) The change ledger's three shell writers, its settings and its schema: tvgw-apply, the
NetworkManager dispatcher and install.sh each append one line to the spool and never fail for it;
LEDGER and JUDGE2_CLEAN_HOURS are checked like every setting; a schema-8 store gains the tables."""

import contextlib
import os
import shutil
import sqlite3
import stat
import subprocess

import pytest
from conftest import ROOT
from test_apply import STUBS, run_apply

from tvgw import config, db

DEPLOY = ROOT / "deploy"
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")

# ip, answering the two routing questions the way the routing already is
ROUTED_IP = STUBS["ip"].replace(
    "exit 0\n",
    'case "$*" in\n'
    "\"rule show priority 60\") printf '60:\\tfrom 10.10.10.0/24 lookup 100 \\n' ;;\n"
    '"route show table 100 default") echo "default via 203.0.113.1 dev wlan0 " ;;\n'
    "esac\nexit 0\n",
)


def spool_lines(tmp_path) -> list[list[str]]:
    path = tmp_path / "state" / "changes.spool"
    return (
        [line.split("\t") for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
    )


@needs_bash
def test_the_apply_appends_who_ran_it_and_whether_it_touched_routing(tmp_path):
    out = run_apply(tmp_path)
    assert out.returncode == 0, out.stderr
    (line,) = spool_lines(tmp_path)
    assert line[1] == "apply" and line[3] == "changed" and line[0].isdigit()
    assert line[2] and all(ch.isalnum() or ch in "_.:+-" for ch in line[2])  # the caller, as a plain word
    out = run_apply(tmp_path, stubs={"ip": ROUTED_IP})
    assert out.returncode == 0, out.stderr
    assert [x[3] for x in spool_lines(tmp_path)] == ["changed", "unchanged"]


@needs_bash
def test_a_spool_that_cannot_be_written_never_fails_the_apply(tmp_path):
    (tmp_path / "state" / "changes.spool").mkdir(parents=True)  # a directory where the file should be
    out = run_apply(tmp_path)
    assert out.returncode == 0, out.stderr
    assert "tvgw: applied" in out.stdout and "changes.spool" not in out.stderr


@contextlib.contextmanager
def umask(mask: int):
    """The umask a child process inherits: systemd's default for a unit, and NetworkManager's."""
    old = os.umask(mask)
    try:
        yield
    finally:
        os.umask(old)


def not_world_readable(path) -> bool:
    return not os.stat(path).st_mode & (stat.S_IROTH | stat.S_IWOTH)


@needs_bash
def test_the_apply_creates_a_spool_others_cannot_read_under_the_default_umask(tmp_path):
    with umask(0o022):
        out = run_apply(tmp_path)
    assert out.returncode == 0, out.stderr
    assert not_world_readable(tmp_path / "state" / "changes.spool")
    assert len(spool_lines(tmp_path)) == 1


def dispatcher(tmp_path, spool: str) -> str:
    text = (DEPLOY / "networkmanager" / "90-tvgw-dispatcher").read_text(encoding="utf-8")
    (tmp_path / "tvgw.conf").write_text("TV_IF=enp1s0\nWAN_IF=wlan1\n", encoding="utf-8")
    (tmp_path / "apply").write_text(f"#!/bin/sh\necho applied >>{tmp_path}/applied\n", encoding="utf-8")
    (tmp_path / "apply").chmod(0o755)
    script = text.replace("/etc/tvgw/tvgw.conf", str(tmp_path / "tvgw.conf"))
    script = script.replace("/usr/local/sbin/tvgw-apply", str(tmp_path / "apply"))
    script = script.replace("/var/lib/tvgw/changes.spool", spool)
    (tmp_path / "dispatcher").write_text(script, encoding="utf-8")
    return str(tmp_path / "dispatcher")


@pytest.mark.skipif(shutil.which("sh") is None, reason="the dispatcher is a POSIX script")
def test_the_dispatcher_logs_every_event_of_its_interfaces_and_still_applies(tmp_path):
    spool = tmp_path / "changes.spool"
    script = dispatcher(tmp_path, str(spool))
    for iface, event in (("enp1s0", "down"), ("enp1s0", "up"), ("tun0", "dhcp4-change"), ("eth9", "up")):
        subprocess.run(["sh", script, iface, event], check=True)
    rows = [line.split("\t")[1:] for line in spool.read_text(encoding="utf-8").splitlines()]
    assert rows == [
        ["dispatcher", "enp1s0", "down"],
        ["dispatcher", "enp1s0", "up"],
        ["dispatcher", "tun0", "dhcp4-change"],
    ]
    assert (tmp_path / "applied").read_text(encoding="utf-8").count("applied") == 2  # up and dhcp4-change


@pytest.mark.skipif(shutil.which("sh") is None, reason="the dispatcher is a POSIX script")
def test_the_dispatcher_creates_a_spool_others_cannot_read_and_logs_wireguard(tmp_path):
    spool = tmp_path / "changes.spool"
    script = dispatcher(tmp_path, str(spool))
    with umask(0o022):
        subprocess.run(["sh", script, "wgpia0", "down"], check=True)
    assert not_world_readable(spool)
    assert [line.split("\t")[1:] for line in spool.read_text(encoding="utf-8").splitlines()] == [
        ["dispatcher", "wgpia0", "down"]
    ]
    assert not (tmp_path / "applied").exists()  # the apply still runs only for tun0, as before


def test_install_creates_the_spool_0640_before_anything_writes_it():
    text = (DEPLOY / "install.sh").read_text(encoding="utf-8")
    create = (
        "[ -e /var/lib/tvgw/changes.spool ] || install -m 640 -g adm /dev/null /var/lib/tvgw/changes.spool"
    )
    assert create in text
    assert "chmod 640 /var/lib/tvgw/changes.spool /var/lib/tvgw/changes.spool.1" in text
    first_apply = text.index("then /usr/local/sbin/tvgw-apply; else systemctl restart tvgw.service")
    assert text.index("install -d -m 2751 -g adm /var/lib/tvgw") < text.index(create) < first_apply


@pytest.mark.skipif(shutil.which("sh") is None, reason="the dispatcher is a POSIX script")
def test_the_dispatcher_applies_when_the_spool_cannot_be_written(tmp_path):
    script = dispatcher(tmp_path, str(tmp_path / "no-such-dir" / "changes.spool"))
    out = subprocess.run(["sh", script, "wlan1", "up"], capture_output=True, text=True, encoding="utf-8")
    assert out.returncode == 0 and out.stderr == ""
    assert (tmp_path / "applied").exists()


def test_install_notes_the_deploy_after_the_restarts_and_never_stops_for_it():
    text = (DEPLOY / "install.sh").read_text(encoding="utf-8")
    (line,) = [ln for ln in text.splitlines() if "--note-deploy" in ln]
    assert line.startswith("tvgw changes --note-deploy ") and "|| echo" in line  # a failure is a note
    assert text.index("restart_changed tvgw-pcap") < text.index(line) < text.index("exec tvgw verify")


def test_the_ledger_settings_are_checked(tmp_path):
    s = config.Settings()
    assert (s.ledger, s.judge2_clean_hours) == ("on", 6)
    conf = tmp_path / "tvgw.conf"
    for bad, why in (
        ("LEDGER=yes", "LEDGER"),
        ("JUDGE2_CLEAN_HOURS=0", "at least 1"),
        ("JUDGE2_CLEAN_HOURS=337", "1 to 336"),
    ):
        conf.write_text(bad + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match=why):
            config.load(conf)
    conf.write_text("LEDGER=off\nJUDGE2_CLEAN_HOURS=12\n", encoding="utf-8")
    assert (config.load(conf).ledger, config.load(conf).judge2_clean_hours) == ("off", 12)
    example = config.parse_conf((DEPLOY / "tvgw.conf.example").read_text(encoding="utf-8"))
    assert example["LEDGER"] == s.ledger and int(example["JUDGE2_CLEAN_HOURS"]) == s.judge2_clean_hours
    readme = (DEPLOY / "README.md").read_text(encoding="utf-8")
    assert "| `LEDGER` | `on` |" in readme and "| `JUDGE2_CLEAN_HOURS` | `6` |" in readme


def test_a_schema_8_store_gains_the_ledger_tables(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(
        "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT); INSERT INTO meta VALUES ('schema', '8');"
        "CREATE TABLE tvstate(t REAL PRIMARY KEY, power TEXT, app TEXT);"
        "INSERT INTO tvstate VALUES (1, 'Active', 'netflix');"
    )
    old.commit()
    old.close()
    conn = db.connect(str(path))
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"changes", "gw_samples", "judge_shadow"} <= tables
    indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert {"changes_t", "changes_event", "judge_shadow_t"} <= indexes
    assert db.get_meta(conn, "schema") == "9" == str(db.SCHEMA_VERSION)
    assert conn.execute("SELECT * FROM tvstate").fetchall() == [(1.0, "Active", "netflix")]
    conn.close()
    db.connect(str(path)).close()  # a second open is a no-op


def test_the_changes_table_keeps_one_row_per_event(tmp_path):
    conn = db.connect(str(tmp_path / "s.db"))
    row = (1.0, 0.0, "sampler", "tv_flap", "eth0", 0, "A")
    sql = "INSERT OR IGNORE INTO changes(t, t_precision, source, kind, subject, controllable, effect_class) VALUES (?,?,?,?,?,?,?)"
    conn.execute(sql, row)
    conn.execute(sql, row)
    assert conn.execute("SELECT COUNT(*) FROM changes").fetchone()[0] == 1
