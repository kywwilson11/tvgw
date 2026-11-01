"""(record) The retention the deploy files set: logrotate's policy, the journald drop-in, and the
install.sh block that writes it, run here on fixtures."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tvgw import config

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
LOGROTATE = (DEPLOY / "logrotate" / "tvgw").read_text(encoding="utf-8")
INSTALL = (DEPLOY / "install.sh").read_text(encoding="utf-8")
TEMPLATE = (DEPLOY / "journald" / "60-tvgw.conf.template").read_text(encoding="utf-8")
BASH = shutil.which("bash")


def stanzas() -> dict[str, dict[str, str]]:
    """Each log path -> its directives (name -> argument)."""
    out: dict[str, dict[str, str]] = {}
    body = re.sub(r"#.*", "", LOGROTATE)
    for paths, block in re.findall(r"([^{}]+)\{([^}]*)\}", body):
        directives = {}
        for line in block.strip().splitlines():
            word, _, arg = line.strip().partition(" ")
            directives[word] = arg
        for path in paths.split():
            assert path not in out, f"{path} named twice: logrotate refuses it"
            out[path] = directives
    return out


def written_logs() -> set[str]:
    """Every log under /var/log/tvgw the units, the nginx files and the code name."""
    found = set()
    for path in [*DEPLOY.rglob("*"), *(ROOT / "src").rglob("*.py")]:
        if path.is_file() and path.suffix != ".md" and path.name != "tvgw":
            text = path.read_text(encoding="utf-8", errors="replace")
            found |= set(re.findall(r"/var/log/tvgw/[A-Za-z0-9_-]+\.log\b", text))
    return found


def test_every_log_tvgw_writes_is_rotated_once_with_the_ingest_s_options():
    rot = stanzas()
    assert written_logs() <= set(rot), written_logs() - set(rot)
    assert not any("*" in path for path in rot), "a glob would name gfts-tls.log twice"
    for path, d in rot.items():
        # the ingest reads `.1` for the lines written just before a rotation, so it must stay plain, and
        # the writers (conntrack's redirect, nginx, tvgw-analyze's >>) never reopen their file
        assert {"copytruncate", "delaycompress", "compress", "missingok", "notifempty"} <= set(d), path


def test_the_spans_are_the_report_s():
    rot = stanzas()
    for log in ("flows.log", "gfts.log"):
        assert rot[f"/var/log/tvgw/{log}"]["rotate"] == "2" and "weekly" in rot[f"/var/log/tvgw/{log}"]
    assert rot["/var/log/tvgw/gfts-tls.log"]["rotate"] == "1"
    history = rot[config.Settings().tvcheck_history]
    assert history["rotate"] == "35" and "daily" in history


def test_the_journald_template_keeps_the_journal_on_disk_for_journal_days():
    lines = [ln for ln in TEMPLATE.splitlines() if ln and not ln.startswith("#")]
    assert lines == [
        "[Journal]",
        "Storage=persistent",
        "MaxRetentionSec=__JOURNAL_DAYS__day",
        "MaxFileSec=1day",
    ]


def test_install_sh_defaults_and_checks_journal_days_as_config_does():
    assert ': "${JOURNAL_DAYS:=14}"' in INSTALL and config.Settings().journal_days == "14"
    assert "^(off|[1-9][0-9]{0,3})$" in INSTALL and "JOURNAL_DAYS > 3650" in INSTALL
    assert config.JOURNAL_MAX_DAYS == 3650
    # the block runs after the logrotate policy is installed, and before any unit is restarted
    at = INSTALL.index("install -m 644 logrotate/tvgw /etc/logrotate.d/tvgw")
    assert at < INSTALL.index("\ntrim_rotations\n") < INSTALL.index("\njournald_dropin\n")
    # (guard) dnsmasq restarts through restart_dnsmasq, defined above; its first call is the first restart
    assert INSTALL.index("\njournald_dropin\n") < INSTALL.index("\trestart_dnsmasq # (guard)")


def block() -> str:
    start = INSTALL.index("# ---- tvgw-journald (record)")
    end = INSTALL.index("# ---- end tvgw-journald ----")
    return INSTALL[start:end]


def bash(script: str, cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    if BASH is None:
        pytest.skip("bash is not installed here")
    return subprocess.run(
        [BASH, "-euo", "pipefail", "-c", block() + script],
        cwd=cwd,
        capture_output=True,
        encoding="utf-8",
        env={"PATH": f"{cwd / 'bin'}:/usr/bin:/bin", **(env or {})},
    )


def test_trim_rotations_removes_the_copies_past_each_log_s_count(tmp_path):
    log, state = tmp_path / "log", tmp_path / "state"
    log.mkdir()
    state.mkdir()
    names = {
        log: [
            "flows.log",
            "flows.log.1",
            "flows.log.2.gz",
            "flows.log.3.gz",
            "flows.log.12.gz",
            "gfts.log.4.gz",
            "gfts-tls.log.1",
            "gfts-tls.log.2.gz",
            "flows.log.bak",
        ],
        state: ["tvcheck-history.log.35.gz", "tvcheck-history.log.36.gz", "tvgw.db"],
    }
    for d, files in names.items():
        for f in files:
            (d / f).write_text("x", encoding="utf-8")
    r = bash(f"trim_rotations {log} {state}", tmp_path)
    assert r.returncode == 0, r.stderr
    assert sorted(p.name for p in log.iterdir()) == [
        "flows.log",
        "flows.log.1",
        "flows.log.2.gz",
        "flows.log.bak",
        "gfts-tls.log.1",
    ]
    assert sorted(p.name for p in state.iterdir()) == ["tvcheck-history.log.35.gz", "tvgw.db"]


OURS = "/etc/systemd/journald.conf.d/60-tvgw.conf"


def cat_config(*files: tuple[str, str]) -> str:
    """What `systemd-analyze cat-config systemd/journald.conf` prints: each file under its path."""
    return "".join(f"# {path}\n[Journal]\n{body}\n\n" for path, body in files)


def note(tmp_path, listing: str) -> str:
    (tmp_path / "listing").write_text(listing, encoding="utf-8")
    r = bash(f"journald_note < {tmp_path / 'listing'}", tmp_path)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_the_note_names_the_owner_s_longer_drop_in_that_tvgw_s_overrides(tmp_path):
    out = note(
        tmp_path,
        cat_config(
            ("/usr/lib/systemd/journald.conf.d/40-rpi-volatile-storage.conf", "Storage=volatile"),
            ("/etc/systemd/journald.conf.d/50-persistent.conf", "Storage=persistent\nMaxRetentionSec=3month"),
            (OURS, "Storage=persistent\nMaxRetentionSec=14day\nMaxFileSec=1day"),
        ),
    )
    assert out.splitlines() == [
        "tvgw: journald: /etc/systemd/journald.conf.d/50-persistent.conf sets MaxRetentionSec=3month;"
        f" {OURS} is read after it and keeps the journal 14day instead, for every service"
        " (JOURNAL_DAYS in tvgw.conf)"
    ]


def test_the_note_says_when_a_later_file_wins(tmp_path):
    out = note(
        tmp_path,
        cat_config(
            (OURS, "MaxRetentionSec=14day"),
            ("/etc/systemd/journald.conf.d/70-site.conf", "MaxRetentionSec=0"),
        ),
    )
    assert "70-site.conf, read after" in out and "longer than tvgw's; the journal keeps no limit" in out
    out = note(
        tmp_path, cat_config((OURS, "MaxRetentionSec=14day"), ("/etc/x/80-short.conf", "MaxRetentionSec=1w"))
    )
    assert "shorter than tvgw's; the journal keeps 1w" in out


@pytest.mark.parametrize("value", ["3fortnight", "1.5x", "forever"])
def test_a_span_the_note_cannot_parse_is_named_and_never_called_longer_or_shorter(tmp_path, value):
    out = note(
        tmp_path,
        cat_config((OURS, "MaxRetentionSec=14day"), ("/etc/x/80-odd.conf", f"MaxRetentionSec={value}")),
    )
    assert out.splitlines() == [
        f"tvgw: journald: /etc/x/80-odd.conf, read after {OURS}, sets MaxRetentionSec={value},"
        f" which tvgw cannot compare with its own; the journal keeps {value}"
    ]
    assert "longer" not in out and "shorter" not in out


def test_infinity_is_no_limit(tmp_path):
    out = note(
        tmp_path,
        cat_config((OURS, "MaxRetentionSec=14day"), ("/etc/x/80-inf.conf", "MaxRetentionSec=infinity")),
    )
    assert "longer than tvgw's; the journal keeps no limit" in out


def test_no_note_for_the_same_span_or_without_tvgw_s_file(tmp_path):
    same = cat_config(
        ("/etc/systemd/journald.conf", "MaxRetentionSec=2week"), (OURS, "MaxRetentionSec=14day")
    )
    assert note(tmp_path, same) == ""
    assert (
        note(
            tmp_path,
            cat_config(("/etc/systemd/journald.conf.d/50-persistent.conf", "MaxRetentionSec=3month")),
        )
        == ""
    )


def test_the_drop_in_is_written_once_and_journald_restarted_only_on_a_change(tmp_path):
    work = tmp_path / "deploy"
    (work / "journald").mkdir(parents=True)
    shutil.copy(DEPLOY / "journald" / "60-tvgw.conf.template", work / "journald")
    (work / "bin").mkdir()
    (work / "bin" / "systemctl").write_text(f'#!/bin/sh\necho "$@" >>{tmp_path}/calls\n', encoding="utf-8")
    (work / "bin" / "systemctl").chmod(0o755)
    dropin = tmp_path / "etc" / "journald.conf.d" / "60-tvgw.conf"
    script = f"JOURNALD_DROPIN={dropin}; journald_dropin"

    def calls() -> list[str]:
        p = tmp_path / "calls"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    r = bash(script, work, {"JOURNAL_DAYS": "14"})
    assert r.returncode == 0, r.stderr
    assert "MaxRetentionSec=14day" in dropin.read_text(encoding="utf-8")
    assert dropin.stat().st_mode & 0o777 == 0o644
    assert calls() == ["restart systemd-journald.service"]
    assert bash(script, work, {"JOURNAL_DAYS": "14"}).returncode == 0
    assert calls() == ["restart systemd-journald.service"], "an unchanged drop-in restarts nothing"
    assert bash(script, work, {"JOURNAL_DAYS": "92"}).returncode == 0
    assert "MaxRetentionSec=92day" in dropin.read_text(encoding="utf-8") and len(calls()) == 2
    assert bash(script, work, {"JOURNAL_DAYS": "off"}).returncode == 0
    assert not dropin.exists() and len(calls()) == 3
    assert bash(script, work, {"JOURNAL_DAYS": "off"}).returncode == 0 and len(calls()) == 3


def test_a_failed_journald_restart_does_not_stop_the_install(tmp_path):
    work = tmp_path / "deploy"
    (work / "journald").mkdir(parents=True)
    shutil.copy(DEPLOY / "journald" / "60-tvgw.conf.template", work / "journald")
    (work / "bin").mkdir()
    (work / "bin" / "systemctl").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (work / "bin" / "systemctl").chmod(0o755)
    dropin = tmp_path / "60-tvgw.conf"
    r = bash(f"JOURNALD_DROPIN={dropin}; journald_dropin; echo after", work, {"JOURNAL_DAYS": "14"})
    assert r.returncode == 0 and r.stdout.strip() == "after"
    assert "applies at the next boot" in r.stderr
