"""Capture v2 (docs/capture.md): the two capture units, the switch between them, the firewall rule the
headers mode reads from, `tvgw verify`'s view of both, and a dumpcap ring through /proc and the ingest.

The units' shell lines run here for real with /bin/sh (and dash where it is installed, the gateway's
/bin/sh), their paths moved under tmp_path; dumpcap itself, systemd and nft are the gateway's to say
(the hardware suite)."""

import os
import re
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from conftest import EMPTY_PCAP, ROOT, UNITS, capture_argv

from tvgw import config, db, ingest, pcaps, verify
from tvgw.config import Settings
from tvgw.pcaps import live_files  # bound at import, before the autouse `fake_live` replaces it

FULL, HEADERS = "tvgw-pcap.service", "tvgw-pcap-headers.service"
APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
SHELLS = [sh for sh in ("/bin/sh", shutil.which("dash")) if sh and os.path.exists(sh)]
CONF = "/etc/tvgw/tvgw.conf"


def unit_lines(unit: str) -> list[str]:
    return (UNITS / unit).read_text(encoding="utf-8").splitlines()


def run_line(unit: str, directive: str, replacements: dict[str, str], shell: str = "/bin/sh"):
    """One `sh -c` Exec line of a unit, run with `shell` and its paths replaced."""
    argv = capture_argv(unit, directive)
    assert argv[:2] == ["/bin/sh", "-c"], argv
    script = argv[2]
    for old, new in replacements.items():
        assert old in script, old
        script = script.replace(old, new)
    return subprocess.run([shell, "-c", script], capture_output=True, text=True, encoding="utf-8", timeout=30)


# ---- which unit runs: the ExecCondition pair ------------------------------------------------------


def conditions(tmp_path, conf: str | None, shell: str) -> tuple[int, int, str]:
    """(full unit's exit, headers unit's exit, their stderr) for a settings file holding `conf`
    (None: no settings file at all)."""
    path = tmp_path / "tvgw.conf"
    if conf is not None:
        path.write_text(conf, encoding="utf-8")
    outs = [run_line(u, "ExecCondition", {CONF: str(path)}, shell) for u in (FULL, HEADERS)]
    return outs[0].returncode, outs[1].returncode, outs[0].stderr + outs[1].stderr


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize(
    ("conf", "expect"),
    [
        (None, (0, 1)),  # a gateway with no settings file captures as it always did
        ("TV_IP=10.10.10.17\n", (0, 1)),  # an older settings file, without the key
        ("CAPTURE_MODE=\n", (0, 1)),  # empty keeps the default, as config.load does
        ("CAPTURE_MODE=full\n", (0, 1)),
        ("CAPTURE_MODE=headers\n", (1, 0)),
        ('CAPTURE_MODE="headers"   # the trial\n', (1, 0)),
        ('CAPTURE_MODE=full # back\nANALYST_WEEKLY_SCHEDULE="Mon 04:10"\n', (0, 1)),
    ],
)
def test_exactly_one_capture_unit_runs_for_each_mode(tmp_path, shell, conf, expect):
    """Exit 0 runs a unit and 1..254 skips it: whatever the setting says, one capture runs and the
    other stands aside, and the settings file is read as the shell scripts read it."""
    full, headers, err = conditions(tmp_path, conf, shell)
    assert (full, headers) == expect, err
    assert err == ""


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize(
    "conf",
    [
        "CAPTURE_MODE=Headers\n",  # a near miss: config.load and tvgw-apply refuse it too
        "CAPTURE_MODE=both\n",
        "CAPTURE_MODE=headers\nfi\n",  # a settings file the shell cannot source
    ],
)
def test_a_mode_neither_unit_can_use_fails_both_instead_of_skipping_both(tmp_path, shell, conf):
    """255 fails the unit, which shows in `systemctl --failed` and in verify's services check; a skip
    there would leave the gateway with no capture and nothing red."""
    full, headers, err = conditions(tmp_path, conf, shell)
    assert (full, headers) == (255, 255), err


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
def test_a_settings_file_the_condition_cannot_read_fails_it(tmp_path):
    """The condition runs as root (+) on the gateway because the file is root:adm 640; were it ever
    to run as the capture user, an unreadable file must fail the unit, never skip it."""
    path = tmp_path / "tvgw.conf"
    path.write_text("CAPTURE_MODE=full\n", encoding="utf-8")
    path.chmod(0)
    try:
        outs = [run_line(u, "ExecCondition", {CONF: str(path)}).returncode for u in (FULL, HEADERS)]
    finally:
        path.chmod(0o600)
    assert outs == [255, 255]


@pytest.mark.parametrize("unit", [FULL, HEADERS])
def test_the_condition_runs_as_root_and_the_capture_does_not(unit):
    """The `+` prefix: only the condition, which reads the settings file, has root."""
    lines = unit_lines(unit)
    (condition,) = [line for line in lines if line.startswith("ExecCondition=")]
    assert condition.startswith("ExecCondition=+/bin/sh -c ")
    assert [line for line in lines if line.startswith(("ExecStart=", "ExecStartPre="))]
    assert not [line for line in lines if re.match(r"Exec\w*=[+!]", line) and line != condition]
    assert "User=tvgw-pcap" in lines


# ---- dumpcap missing --------------------------------------------------------------------------------


@pytest.mark.parametrize("unit", [FULL, HEADERS])
def test_a_missing_or_unusable_dumpcap_fails_the_start_with_a_message_that_says_what_to_install(
    tmp_path, unit
):
    dumpcap = tmp_path / "dumpcap"
    missing = run_line(unit, "ExecStartPre", {"/usr/bin/dumpcap": str(dumpcap)})
    assert missing.returncode == 1 and "wireshark-common" in missing.stderr
    dumpcap.write_text("#!/bin/sh\n", encoding="utf-8")
    dumpcap.chmod(0o644)  # installed for the wireshark group only: not executable by tvgw-pcap
    if os.geteuid() != 0:
        assert run_line(unit, "ExecStartPre", {"/usr/bin/dumpcap": str(dumpcap)}).returncode == 1
    dumpcap.chmod(0o755)
    usable = run_line(unit, "ExecStartPre", {"/usr/bin/dumpcap": str(dumpcap)})
    assert (usable.returncode, usable.stderr) == (0, "")


# ---- the two units side by side ---------------------------------------------------------------------

SANDBOX = re.compile(
    r"^(User|Group|AmbientCapabilities|CapabilityBoundingSet|NoNewPrivileges|UMask|Protect\w+|PrivateTmp|"
    r"ReadWritePaths|RestrictAddressFamilies|SystemCallArchitectures|RestrictRealtime|Environment|"
    r"Restart|RestartSec)="
)


def test_both_units_run_with_the_same_user_sandbox_and_directory():
    """The headers capture writes into the same directory for the same extractor, so it must make
    the same files (640 tvgw-pcap:nogroup) under the same limits; a difference is a mistake."""
    full, headers = ([line for line in unit_lines(u) if SANDBOX.match(line)] for u in (FULL, HEADERS))
    assert full == headers and "ReadWritePaths=/var/lib/tvgw/pcap" in full
    for unit in (FULL, HEADERS):
        argv = capture_argv(unit)
        assert os.path.dirname(argv[argv.index("-w") + 1]) == Settings().pcap_dir
        # without -g dumpcap creates ring files 0600: unreadable to the extractor (nobody), the
        # 2026-10-27 incident again
        assert "-g" in argv and "UMask=0027" in unit_lines(unit)


def test_one_switch_starts_stops_and_restarts_both_units():
    """install.sh enables, starts and restarts tvgw-pcap only (it is not this workstream's file):
    tvgw-pcap wants the headers unit, and the headers unit is part of tvgw-pcap, so it needs no
    enable of its own and is never left running beside the other after a restart."""
    assert "Wants=tvgw-pcap-headers.service" in unit_lines(FULL)
    headers = unit_lines(HEADERS)
    assert "PartOf=tvgw-pcap.service" in headers
    assert "[Install]" not in headers  # static: started through tvgw-pcap, never enabled alone
    assert "After=tvgw.service" in headers and "Wants=tvgw.service" in headers


def test_the_headers_unit_reads_the_group_the_firewall_logs_to():
    group = re.search(r"^CAPTURE_GROUP=(\d+)$", APPLY, re.M)
    assert group, "tvgw-apply names its NFLOG group"
    argv = capture_argv(HEADERS)
    assert argv[argv.index("-i") + 1] == f"nflog:{group.group(1)}"
    assert "-f" not in argv  # the rule chose the packets; a BPF filter on nflog runs in userspace
    assert verify.CAPTURE_UNITS == {"full": "tvgw-pcap", "headers": "tvgw-pcap-headers"}


def test_the_full_unit_captures_on_the_tv_interface_and_rotates_on_the_clock():
    argv = capture_argv(FULL)
    assert argv[argv.index("-i") + 1] == Settings().tv_if
    assert argv[argv.index("-s") + 1] == "0"  # whole frames: requests to port 80 are kept whole
    assert argv.index("-i") < argv.index("-f")  # dumpcap applies -f to the -i before it


# ---- the firewall side: tvgw-apply's capture block --------------------------------------------------


def capture_block() -> str:
    start = APPLY.index("# ---- (capture) begin: position-based capture")
    return APPLY[start : APPLY.index("# ---- (capture) end ----", start)]


def test_the_capture_block_is_delimited_and_cannot_return_a_verdict():
    """The block's rules only count and log: no accept, drop, reject, jump or NAT, so a mistake in it
    can lose evidence but never let a packet through or stop one."""
    block = capture_block()
    rules = [line.strip() for line in block.splitlines() if line.strip().startswith('iifname "$TV_IF"')]
    assert len(rules) == 2
    for rule in rules:
        words = set(re.findall(r"[a-z]+", rule.split(" comment ")[0]))
        assert not words & {"accept", "drop", "reject", "jump", "goto", "return", "dnat", "snat", "queue"}
        assert " log group $CAPTURE_GROUP" in rule and " counter " in rule
    assert "policy accept;" in block and "hook prerouting priority mangle - 5" in block
    assert APPLY.count("# ---- (capture) begin") == APPLY.count("# ---- (capture) end ----") == 2


def test_the_rule_bounds_each_connection_and_skips_one_conntrack_kept_no_counters_for():
    rules = [line.strip() for line in capture_block().splitlines() if "log group" in line]
    first, http = rules
    assert "ct original packets != 0 ct original packets <= $CAPTURE_PACKETS" in first
    assert "snaplen $CAPTURE_SNAPLEN" in first
    assert "tcp dport 80 ct original packets > $CAPTURE_PACKETS" in http  # after them: never twice
    assert re.search(r"^CAPTURE_PACKETS=8$", APPLY, re.M) and re.search(
        r"^CAPTURE_SNAPLEN=4096$", APPLY, re.M
    )
    assert verify.CAPTURE_RULE in first


def test_the_settings_reference_and_choices_agree():
    assert Settings().capture_mode == "full"
    assert config.CHOICES["CAPTURE_MODE"] == ("full", "headers")
    assert "CAPTURE_MODE" in verify.APPLY_KEYS


def test_capture_mode_is_read_and_a_near_miss_refused(tmp_path):
    conf = tmp_path / "tvgw.conf"
    conf.write_text("CAPTURE_MODE=headers  # the trial\n", encoding="utf-8")
    assert config.load(conf).capture_mode == "headers"
    conf.write_text("CAPTURE_MODE=Headers\n", encoding="utf-8")
    with pytest.raises(ValueError, match="CAPTURE_MODE='Headers'"):
        config.load(conf)


# ---- tvgw verify --------------------------------------------------------------------------------

CAPTURE_TABLE = f"""table inet tvgw_capture {{
	chain pre {{
		type filter hook prerouting priority mangle - 5; policy accept;
		iifname "eth0" ip saddr 10.10.10.0/24 ip saddr != 10.10.10.1 ct original packets != 0 ct original packets <= 8 counter packets 40 bytes 9000 log group 7 snaplen 4096 comment "{verify.CAPTURE_RULE}"
	}}
}}
"""


def fake_run(states: dict[str, str], tables: dict[str, str] | None = None):
    """`systemctl is-active` and `nft list table` answers; everything else is empty."""
    tables = tables or {}

    def run(cmd):
        if cmd[:2] == ["systemctl", "is-active"]:
            return "".join(states.get(u, "inactive") + "\n" for u in cmd[2:])
        if cmd[:3] == ["nft", "list", "table"]:
            return tables.get(cmd[4], "")
        return ""

    return run


def test_verify_full_mode_passes_with_tvgw_pcap_alone():
    s = Settings()
    check = verify.capture_check(s, fake_run({"tvgw-pcap": "active"}))
    assert (check.ok, check.detail) == (True, "full: tvgw-pcap on eth0")


def test_verify_fails_when_both_captures_run():
    """Changing the setting and starting only the other unit leaves both writing one directory, and
    every hello counted twice."""
    both = fake_run({"tvgw-pcap": "active", "tvgw-pcap-headers": "active"}, {"tvgw_capture": CAPTURE_TABLE})
    for mode in ("full", "headers"):
        check = verify.capture_check(Settings(capture_mode=mode), both)
        assert not check.ok and "sudo systemctl restart tvgw-pcap" in check.detail
        assert ("tvgw-pcap-headers is running" if mode == "full" else "tvgw-pcap is running") in check.detail


def test_verify_headers_mode_needs_the_rule_that_feeds_the_capture():
    s = Settings(capture_mode="headers")
    alone = {"tvgw-pcap-headers": "active"}
    missing = verify.capture_check(s, fake_run(alone))
    assert not missing.ok and "sudo tvgw-apply" in missing.detail
    held = verify.capture_check(s, fake_run(alone, {"tvgw_capture": CAPTURE_TABLE}))
    assert (held.ok, held.detail) == (True, "headers: tvgw-pcap-headers on nflog:7")


def test_verify_expects_the_unit_the_mode_names_in_the_services_check(lg):
    """In headers mode tvgw-pcap is condition-skipped (inactive), and that is right; the headers unit
    being down is the outage."""
    s = Settings(capture_mode="headers", dnsgate="off")
    seen: list[list[str]] = []

    def run(cmd):
        seen.append(cmd)
        return fake_run({"tvgw-pcap-headers": "active"}, {"tvgw_capture": CAPTURE_TABLE})(cmd)

    r = verify.check(s, lg, run=run, read=lambda p: "", mtime=lambda p: None, resolve=lambda n: None)
    (services,) = [c[2:] for c in seen if c[:2] == ["systemctl", "is-active"] and len(c) > 3]
    assert "tvgw-pcap-headers" in services and "tvgw-pcap" not in services
    by_name = {c.name: c for c in r.checks}
    assert "tvgw-pcap-headers" not in by_name["services"].detail and by_name["capture"].ok
    assert ["nft", "-j", "list", "table", "inet", "tvgw_capture"] in seen  # its counters, for the record
    full = []
    verify.check(
        replace(s, capture_mode="full"),
        lg,
        run=lambda c: full.append(c) or "",
        read=lambda p: "",
        mtime=lambda p: None,
        resolve=lambda n: None,
    )
    assert ["nft", "-j", "list", "table", "inet", "tvgw_capture"] not in full


def test_a_conf_switched_to_headers_and_not_applied_is_stale():
    """applied_current: CAPTURE_MODE is a key tvgw-apply reads, so an edit nobody applied is one."""
    used = "UPLINK=direct\nWAN_IF=wlan0\nWAN_GW=203.0.113.1\nCAPTURE_MODE=full\n"
    now = used.replace("CAPTURE_MODE=full", "CAPTURE_MODE=headers")
    assert verify.apply_settings(used) != verify.apply_settings(now)
    # a record from an apply that predates the key reads as the default, so nothing turns stale
    assert verify.apply_settings(used.replace("CAPTURE_MODE=full\n", "")) == verify.apply_settings(used)


# ---- a dumpcap ring through /proc and the ingest ------------------------------------------------


def fake_proc(root: Path, processes: dict[str, tuple[str, dict[str, str]]]) -> str:
    for pid, (comm, fds) in processes.items():
        (root / pid / "fd").mkdir(parents=True)
        (root / pid / "comm").write_text(comm + "\n", encoding="utf-8")
        for fd, target in fds.items():
            os.symlink(target, root / pid / "fd" / fd)
    return str(root)


def test_the_file_dumpcap_holds_is_live_and_a_reader_holding_one_is_not(tmp_path):
    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    live, read = pcap_dir / "tv_20261101120000_00002.pcap", pcap_dir / "tv_20261101110000_00001.pcap"
    proc = fake_proc(
        tmp_path / "proc",
        {
            "10": ("dumpcap", {"3": str(live), "4": "socket:[1]"}),
            "11": ("tshark", {"3": str(read)}),  # the extractor reading a finished hour
            "12": ("tcpdump", {"1": "pipe:[2]"}),  # the DNS-gate feeder: holds no pcap here
        },
    )
    assert live_files(str(pcap_dir), proc=proc) == {os.path.realpath(live)}
    assert sorted(pcaps.WRITERS) == ["dumpcap", "tcpdump"]


def test_the_tcpdump_files_left_by_the_switch_and_the_dumpcap_ring_are_read_alike(tmp_path):
    """The deploy that switches leaves the last tcpdump hours beside the first dumpcap ones, and a
    headers trial adds its own prefix; all are finished by the same rule, the old names first."""
    names = [
        "tv-20261101T100000Z.pcap",
        "tv-20261101T110000Z.pcap",
        "tv_20261101115959_00001.pcap",
        "tv_20261101120000_00002.pcap",
        "tvhdr_20261102120000_00001.pcap",
    ]
    for name in names:
        (tmp_path / name).write_bytes(EMPTY_PCAP)
    live = {os.path.realpath(tmp_path / "tvhdr_20261102120000_00001.pcap")}
    assert [os.path.basename(p) for p in pcaps.finished(str(tmp_path), live)] == names[:-1]


def ring_gateway(gateway, *names: str) -> Path:
    directory = Path(gateway.pcap_dir)
    for f in directory.iterdir():
        f.unlink()
    for name in names:
        (directory / name).write_bytes(EMPTY_PCAP)
    return directory


def test_a_dumpcap_rotation_between_the_listing_and_proc_reads_only_the_closed_hour(gateway):
    """dumpcap closes the hour's file, then opens the next. Whether /proc is read in the gap (nothing
    held) or after the open (the new file held), the closed file is read once and the new one, which
    the listing did not see, waits for the next run, as the tcpdump ring's did."""
    for opened_before_proc in (False, True):
        directory = ring_gateway(gateway, "tv_20261101110000_00001.pcap")
        conn = db.connect(gateway.db_path)
        conn.execute("DELETE FROM pcaps_done")
        seen: list[str] = []

        def rotate(_pcap_dir, opened=opened_before_proc, directory=directory):
            new = directory / "tv_20261101120000_00002.pcap"
            new.write_bytes(b"" if opened else EMPTY_PCAP)
            return {os.path.realpath(new)} if opened else set()

        def extract(path, seen=seen):
            seen.append(os.path.basename(path))
            return []

        warnings: list[str] = []
        assert ingest.ingest_pcaps(conn, gateway, extract, warnings.append, rotate) == (1, 0, 0, 0)
        assert (seen, warnings) == (["tv_20261101110000_00001.pcap"], [])
        names = {r[0] for r in conn.execute("SELECT name FROM pcaps_done")}
        assert names == {"tv_20261101110000_00001.pcap"}, opened_before_proc
        conn.close()


def test_the_open_ring_file_is_never_extracted_and_is_read_once_closed(gateway):
    directory = ring_gateway(gateway, "tv_20261101110000_00001.pcap", "tv_20261101120000_00002.pcap")
    conn = db.connect(gateway.db_path)
    seen: list[str] = []
    hour = {os.path.realpath(directory / "tv_20261101120000_00002.pcap")}

    def extract(path):
        seen.append(os.path.basename(path))
        return []

    assert ingest.ingest_pcaps(conn, gateway, extract, print, lambda d: hour)[0] == 1
    assert ingest.ingest_pcaps(conn, gateway, extract, print, lambda d: set())[0] == 1  # closed now
    assert ingest.ingest_pcaps(conn, gateway, extract, print, lambda d: set())[0] == 0  # once only
    assert seen == ["tv_20261101110000_00001.pcap", "tv_20261101120000_00002.pcap"]
    assert ingest.deletable_pcaps(conn) == set(seen)
    conn.close()
