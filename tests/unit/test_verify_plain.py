"""(plain) verify's plain layer: every check has a meaning, what you notice and a fix in plain words, sits in
exactly one of the five groups setup prints, and is named in the status file only by its name."""

import json
import os
import re
import stat

import pytest
from conftest import NOW, ROOT, load_tool
from test_verify import S, gateway, patch_gateway, resolver

from tvgw import cli, guard, probe, verify
from tvgw.verify import Check, Result

SOURCE = (ROOT / "src" / "tvgw" / "verify.py").read_text(encoding="utf-8")
UNITS = {p.name for p in (ROOT / "deploy" / "systemd").iterdir()}
OTHER_UNITS = {"AdGuardHome", "dnsmasq", "nginx"}  # installed by their own packages, run by tvgw's install
docgen = load_tool("docgen")
# a command in a plain text, as docs/reference/verify-checks.md shows it in a code span: `sudo` and a
# program, then words of letters, digits and - < > / _, with a dot only inside a word
COMMAND = docgen.COMMAND
# engineering words a reader who is not an engineer does not know, kept out of what a check means and what
# you notice, and out of a fix but for its commands; a settings key is one too
JARGON = re.compile(
    r"\b(nftables|nft|netdev|inet|dnsmasq|nginx|conntrack|dumpcap|NetworkManager|DoH|DoT|DoQ|QUIC|SDP|"
    r"GFTS|MQTT|SQLite|canary|probation|judge|shadow|guard|sudoedit|debconf|PYTHONPATH|venv|LAN API|"
    r"must-allow|ruleset|chain|sysctl|sentinels?|drop-in|DNAT|NAT|cgroup|design decision)\b"
    r"|\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b"
)


def names_in_source() -> list[str]:
    """Every check name verify.py can produce, in the order the source names them: each Check is built
    with its name as a literal, which the first assertion below holds the source to."""
    return list(dict.fromkeys(re.findall(r'\bCheck\(\s*"([a-z0-9_]+)"', SOURCE)))


def test_every_check_verify_can_run_has_a_plain_entry_in_run_order(lg):
    """Fails when a new check lands without its plain words, as test_deploy_lint.py fails on a
    KEY_RULES needle tvgw-apply lacks; and when an entry outlives its check."""
    assert not re.search(r"\bCheck\(\s*[^\s\")]", SOURCE), "a Check whose name is not a literal"
    names = names_in_source()
    assert sorted(names) == sorted(verify.PLAIN), set(names) ^ set(verify.PLAIN)
    # every check, passing: the direct uplink runs policy_rule and the DNS gate is on, so dnsgate runs;
    # (probe) and a probe is handed in, as the recorded run of a gateway with TV_PROBE=on hands one in
    passed = lambda: probe.Verdict(probe.PASS)  # noqa: E731
    run = [c.name for c in verify.check(S, lg, **gateway(), resolve=resolver(), probe=passed).checks]
    assert run == list(verify.PLAIN)  # the scan found what a run makes, and PLAIN is in run order


def test_every_check_is_in_exactly_one_group_and_the_groups_are_the_five_setup_prints():
    seen = [name for names in verify.GROUPS.values() for name in names]
    assert sorted(seen) == sorted(verify.PLAIN), set(seen) ^ set(verify.PLAIN)
    assert len(seen) == len(set(seen)), "a check in two groups"
    assert list(verify.GROUPS) == [
        "the TV's cable leads to the internet only through this computer",
        "the TV's lookups go through the filter",
        "recording what the TV does",
        "every service is running",
        "the TV has no second way out",
    ]
    assert verify.UNGROUPED not in verify.GROUPS


def test_the_settling_checks_are_checks():
    assert set(verify.PLAIN) >= verify.SETTLING
    assert sorted(verify.SETTLING) == [
        "capture",
        "doh4_fresh",
        "doh4_loaded",
        "flowlog_events",
        "list_sentinels",
        "resolver_must_allow",
        "services",
    ]


def sentences(text: str) -> list[str]:
    return [s for s in re.split(r"(?<=[.:])\s+(?=[A-Z])", text) if s]


def test_the_plain_words_are_plain():
    """Short sentences (none over 35 words, a mean of at most 18) and no engineering term outside a
    command. Each part is whole sentences."""
    lengths = []
    for name, parts in verify.PLAIN.items():
        assert len(parts) == 3 and all(isinstance(p, str) and p for p in parts), name
        for part in parts:
            assert part[0].isupper() and part.endswith("."), (name, part)
            assert part == part.strip() and "  " not in part, (name, part)
            assert not JARGON.search(COMMAND.sub("", part)), (name, part)
            assert "|" not in part and "`" not in part, (name, part)  # they go into a markdown table as is
            for sentence in sentences(part):
                lengths.append(len(sentence.split()))
                assert lengths[-1] <= 35, (name, sentence)
    assert sum(lengths) / len(lengths) <= 18


def commands() -> set[str]:
    return {m for parts in verify.PLAIN.values() for part in parts for m in COMMAND.findall(part)}


def test_every_command_a_fix_names_exists_in_this_version():
    """A tvgw command parses with tvgw's own parser; a unit is one tvgw ships, or AdGuard Home, dnsmasq or
    nginx; tvgw-apply and the installer are the files the package installs. `<name>` stands for the
    unit sudo tvgw verify names."""
    found = commands()
    assert "sudo tvgw-apply" in found and "sudo tvgw verify" in found
    parser = cli.build_parser()
    for command in sorted(found):
        argv = command.removeprefix("sudo ").split()
        program, args = argv[0], argv[1:]
        if program == "tvgw":
            parser.parse_args(args)  # SystemExit on a subcommand or a flag tvgw does not have
        elif program == "tvgw-apply":
            assert args == [] and (ROOT / "deploy" / "nftables" / "tvgw-apply").is_file()
        elif program == "tvgw-doh-update":  # (listguard) its one option takes a refresh it held back
            assert args in ([], ["--accept"]) and (ROOT / "deploy" / "bin" / "tvgw-doh-update").is_file()
            assert "--accept)" in (ROOT / "deploy" / "bin" / "tvgw-doh-update").read_text(encoding="utf-8")
        elif program.endswith("install.sh"):
            assert args == [] and (ROOT / "deploy" / "install.sh").is_file(), command
            assert program in ("/usr/lib/tvgw/deploy/install.sh", "deploy/install.sh"), command
        elif program in ("systemctl", "journalctl"):
            if program == "systemctl":
                verb, *rest = args
                assert verb in ("start", "restart", "reload-or-restart", "enable"), command
                rest = [a for a in rest if a != "--now"]
                assert verb != "enable" or "--now" in args, command
            else:
                assert args[0] == "-u" and args[2:] in (["-n", "20"], ["-n", "50"]), command
                rest = [args[1]]
            (unit,) = rest
            known = unit == "<name>" or unit in OTHER_UNITS or f"{unit}.service" in UNITS or unit in UNITS
            assert known, command
        else:
            pytest.fail(f"unchecked command {command!r}")
    packaged = (ROOT / "packaging" / "nfpm.yaml").read_text(encoding="utf-8")
    assert "dst: /usr/lib/tvgw/deploy" in packaged  # where the package puts the installer


def test_the_fixes_never_restart_tvgw_service():
    """A restart of an active tvgw.service runs its stop, which switches the TV's forwarding off: the
    plain fixes start it, which does nothing to one already running."""
    assert not any(
        re.search(r"restart tvgw\b(?!-)", part) for parts in verify.PLAIN.values() for part in parts
    )


def test_the_verify_checks_page_shows_the_plain_words_as_the_code_has_them():
    """docs/reference/verify-checks.md carries GROUPS, SETTLING and PLAIN under "In plain words" as
    tools/docgen.py writes them from the code, one row per check in run order, each command in a code
    span; `make docgen` writes it again after a change."""
    page = (ROOT / "docs" / "reference" / "verify-checks.md").read_text(encoding="utf-8")
    plain_part = page.split("## In plain words\n", 1)[1].split("\n## ", 1)[0]
    (region,) = [r for r in docgen.regions("verify-checks.md", plain_part) if r.name == "verify-checks"]
    assert region.body == docgen.render("verify-checks"), "the plain table differs from the code: make docgen"
    rows = [line for line in region.body.split("\n") if line.startswith("| `")]
    assert [row.split("`")[1] for row in rows] == list(verify.PLAIN)
    for row, parts in zip(rows, verify.PLAIN.values(), strict=True):
        assert row.endswith(" | ".join(COMMAND.sub(lambda m: f"`{m[0]}`", p) for p in parts) + " |")
    for sentence, names in verify.GROUPS.items():
        assert f"- {sentence}: " + ", ".join(f"`{n}`" for n in names) + "\n" in region.body
    assert all(
        f"`{n}`" in region.body.split("The settling checks")[1].split("\n")[0] for n in verify.SETTLING
    )


def test_the_new_checks_table_is_fail_after_and_promoted():
    page = (ROOT / "docs" / "reference" / "verify-checks.md").read_text(encoding="utf-8")
    (region,) = [r for r in docgen.regions("verify-checks.md", page) if r.name == "verify-new-checks"]
    assert region.body == docgen.render("verify-new-checks")
    rows = {line.split("`")[1]: line for line in region.body.split("\n") if line.startswith("| `")}
    assert list(rows) == [n for n in verify.PLAIN if n in verify.FAIL_AFTER]
    for name, row in rows.items():
        now = "WARN at most" if name not in verify.PROMOTED else verify.FAIL_AFTER[name].upper()
        assert row.startswith(f"| `{name}` | {now} | "), row


def run_of(*checks: Check) -> Result:
    return Result(checks=list(checks), t=NOW + 0.75)


def test_by_group_keeps_the_group_order_and_the_run_order_and_never_hides_a_check():
    r = run_of(
        Check("services", False, "down: nginx"),
        Check("tv_paths", True),
        Check("ruleset", True),
        Check("brand_new", False),
        Check("forwarding", True),
    )
    assert [(sentence, [c.name for c in members]) for sentence, members in verify.by_group(r)] == [
        ("the TV's cable leads to the internet only through this computer", ["ruleset", "forwarding"]),
        ("every service is running", ["services"]),
        ("the TV has no second way out", ["tv_paths"]),
        (verify.UNGROUPED, ["brand_new"]),
    ]
    assert verify.by_group(run_of()) == []


def test_settling_failures_are_the_failed_checks_that_may_still_pass_on_their_own():
    r = run_of(
        Check("list_sentinels", False),
        Check("ruleset", False),
        Check("services", False),
        Check("doh4_loaded", True),
        Check("capture", True, warn=True),
    )
    assert verify.settling_failures(r) == ["list_sentinels", "services"]
    assert verify.settling_failures(run_of(Check("ruleset", False))) == []


def test_the_status_line_is_the_verdict_by_check_name():
    ok = run_of(Check("ruleset", True), Check("dnsgate", True, "3 of 4", warn=True))
    assert verify.status_line(ok) == f"ok {int(NOW)} 2\n"  # a WARN passed
    bad = run_of(Check("ruleset", False, "missing: NAT"), Check("tv_route", True), Check("services", False))
    assert verify.status_line(bad) == f"fail {int(NOW)} ruleset services\n"


def test_every_run_writes_the_status_file_whole_and_readable_by_all(lg, monkeypatch, status_file, capsys):
    patch_gateway(monkeypatch, gateway())
    assert verify.main(S, lg) == 0
    # every check but tv_probe, which only a recorded run of a gateway with TV_PROBE=on makes
    assert status_file.read_text(encoding="utf-8") == f"ok {int(NOW)} {len(verify.PLAIN) - 1}\n"
    assert stat.S_IMODE(os.stat(status_file).st_mode) == 0o644
    assert os.listdir(status_file.parent) == ["status.txt"]  # no temporary file left beside it
    capsys.readouterr()
    assert verify.main(S, lg, as_json=True) == 0  # --json writes it too, and keeps stdout to the JSON
    json.loads(capsys.readouterr().out)
    assert status_file.read_text(encoding="utf-8").startswith("ok ")


def test_the_status_file_names_failed_checks_and_never_a_detail(lg, monkeypatch, status_file):
    """The details of these failures carry an uplink, an address and a USB adapter's MAC-bearing name;
    the file carries the check names alone."""
    route = ("ip", "-j", "route", "get", "1.1.1.1", "from", "10.10.10.17", "iif", "eth0")
    host = gateway(
        {
            route: json.dumps([{"dst": "1.1.1.1", "dev": "enx00005e005301", "gateway": "192.0.2.1"}]),
            ("systemctl", "is-active", *verify.SERVICES, "tvgw-dnsgate"): "inactive\n",
        }
    )
    patch_gateway(monkeypatch, host)
    monkeypatch.setattr(verify.dnsq, "a_records", lambda name, server, timeout=4.0: ["198.51.100.9"])
    assert verify.main(S, lg) == 1
    text = status_file.read_text(encoding="utf-8")
    failed = [
        c.name for c in verify.check(S, lg, **host, resolve=lambda n: ["198.51.100.9"]).checks if not c.ok
    ]
    assert {"tv_route", "services", "resolver_rewrite"} <= set(failed)
    assert text == f"fail {int(NOW)} {' '.join(failed)}\n"
    assert re.fullmatch(r"fail \d+( [a-z0-9_]+)+\n", text)
    for identifier in ("enx", "00005e", "192.0.2", "198.51.100", "wlan0", "eth0", "10.10.10"):
        assert identifier not in text


def test_a_status_that_cannot_be_written_never_changes_the_verdict(lg, monkeypatch, tmp_path, capsys):
    patch_gateway(monkeypatch, gateway())
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    monkeypatch.setattr(verify, "STATUS", str(blocker / "status.txt"))
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert verify.main(S, lg) == 0
    assert capsys.readouterr().err == ""  # an unprivileged run cannot replace root's file: nothing to say
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert verify.main(S, lg) == 0
    err = capsys.readouterr().err
    assert err.startswith(f"tvgw verify: could not write {blocker / 'status.txt'}: ") and err.count("\n") == 1


def test_a_write_cut_short_leaves_the_last_status_and_no_temporary_file(monkeypatch, status_file):
    verify.write_status(run_of(Check("ruleset", True)), str(status_file))
    before = status_file.read_text(encoding="utf-8")

    def power_cut(src, dst):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(guard.os, "replace", power_cut)
    verify.write_status(run_of(Check("ruleset", False)), str(status_file))
    assert status_file.read_text(encoding="utf-8") == before == f"ok {int(NOW)} 1\n"
    assert os.listdir(status_file.parent) == ["status.txt"]


def test_no_unit_test_writes_the_real_status_file():
    """conftest's status_file points every test's runs at the session's own directory: a unit test run as
    root on a gateway must never replace the gateway's status."""
    assert verify.STATUS != "/run/tvgw/status.txt" and verify.STATUS.endswith("status.txt")
