"""(depth) `tvgw doctor` through a fake Env: each fix path, the per-unit commands, the lock, the questions.

The doctor runs verify's checks, explains each one that did not pass in verify.PLAIN's words, and offers a
fix. It needs root, takes the install lock before any fix and checks again under it, never restarts an
active tvgw.service, reloads the guard, sends AdGuard Home through `tvgw adguard service`, probes the
internet before a lookup fix, explains another firewall without touching it, and always ends with the
cable sentence.
"""

import contextlib
import dataclasses
import json

import pytest
from test_verify import S

from tvgw import cli, doctor, verify
from tvgw.verify import Check, Result

AGH_JOURNAL = ("journalctl", "-u", "AdGuardHome", "-n", "5", "-o", "cat")
HEALTHY_PROBES = {
    ("ip", "-j", "route", "show", "default", "dev", "wlan0"): (
        0,
        json.dumps([{"dst": "default", "gateway": "198.51.100.1", "dev": "wlan0"}]),
    ),
    ("ip", "-j", "neigh", "show", "dev", "wlan0", "198.51.100.1"): (
        0,
        json.dumps([{"dst": "198.51.100.1", "lladdr": "00:00:5e:00:53:01", "state": ["REACHABLE"]}]),
    ),
}


class Fake:
    """An Env whose every touch is recorded: the commands run, what was said, the questions asked, and
    whether each command ran under the lock."""

    def __init__(self, runs, answers=(), root=True, tty=True, commands=None, files=None, resolve=None):
        self.runs = list(runs)  # the Results check() returns, one per call (the last one repeats)
        self.answers = list(answers)
        self.root, self.tty = root, tty
        self.commands = {**HEALTHY_PROBES, **(commands or {})}
        self.files = {"/sys/class/net/wlan0/carrier": "1\n", **(files or {})}
        self.resolved = resolve or (lambda name: ["192.0.2.80"])
        self.ran: list[tuple[str, ...]] = []
        self.locked_runs: list[tuple[str, ...]] = []
        self.said: list[str] = []
        self.asked: list[str] = []
        self.checks = 0
        self.in_lock = False
        self.lock_taken = 0
        self.trimmed = 0
        self.lock_error: Exception | None = None
        self.statuses: list[Result] = []

    def check(self):
        self.checks += 1
        return self.runs[min(self.checks - 1, len(self.runs) - 1)]

    def run(self, argv):
        argv = tuple(argv)
        self.ran.append(argv)
        if self.in_lock:
            self.locked_runs.append(argv)
        if argv == ("systemctl", "is-active", "tvgw.service"):
            return 0, self.commands.get(argv, (0, "active\n"))[1]
        return self.commands.get(argv, (0, ""))

    def ask(self, question):
        self.asked.append(question)
        return self.answers.pop(0) if self.answers else False

    @contextlib.contextmanager
    def lock(self):
        if self.lock_error:
            raise self.lock_error
        self.lock_taken += 1
        self.in_lock = True
        try:
            yield 8
        finally:
            self.in_lock = False

    def trim(self):
        self.trimmed += 1
        return ["tvgw-20261020T034000Z.db", "tvgw-20261021T034000Z.db"]

    def env(self) -> doctor.Env:
        return doctor.Env(
            check=self.check,
            run=self.run,
            read=lambda path: self.files.get(path, ""),
            resolve=self.resolved,
            say=self.said.append,
            ask=self.ask,
            interactive=lambda: self.tty,
            is_root=lambda: self.root,
            lock=self.lock,
            trim_backups=self.trim,
            status=self.statuses.append,
        )

    @property
    def text(self) -> str:
        return "\n".join(self.said)


def result(*checks: Check) -> Result:
    passing = [Check("ruleset", True), Check("tv_route", True, "via wlan0, expected wlan0")]
    return Result(checks=[*passing, *checks], t=1.0)


OK_RUN = result()


def doc(fake, lg, **kw) -> int:
    return doctor.main(S, lg, fake.env(), **kw)


def test_refuses_without_root_and_does_nothing(lg):
    fake = Fake([result(Check("forwarding", False, "ip_forward=0 (TV offline)"))], root=False)
    assert doc(fake, lg, yes=True) == 1
    assert fake.said == ["tvgw doctor: run it as root, with: sudo tvgw doctor", doctor.BYPASS]
    assert fake.checks == 0 and fake.ran == [] and fake.lock_taken == 0


def test_a_healthy_gateway_says_so_and_ends_with_the_cable(lg):
    fake = Fake([OK_RUN])
    assert doc(fake, lg) == 0
    assert fake.said == ["tvgw doctor: all 2 checks pass. The gateway holds.", doctor.BYPASS]
    assert doctor.BYPASS == (
        "If the TV still has no internet: move its cable from the gateway to your router; tvgw keeps its settings."
    )


def test_each_finding_is_explained_in_plain_words_then_asked(lg):
    fake = Fake([result(Check("forwarding", False, "ip_forward=0 (TV offline)")), OK_RUN], answers=[True])
    assert doc(fake, lg) == 0
    what, notice, fix = verify.PLAIN["forwarding"]
    i = fake.said.index("FAIL forwarding: ip_forward=0 (TV offline)")
    assert fake.said[i + 1 : i + 4] == [
        f"  What it means: {what}",
        f"  What you notice: {notice}",
        f"  The fix: {fix}",
    ]
    assert fake.asked == ["  Do it now?"]
    assert fake.said[-1] == doctor.BYPASS and "Now: no check fails." in fake.said


def test_the_firewall_fix_runs_tvgw_apply_on_an_active_unit_under_the_lock(lg):
    fake = Fake([result(Check("applied_current", False, "changed after the last apply: tvgw.conf")), OK_RUN])
    assert doc(fake, lg, yes=True) == 0
    assert fake.lock_taken == 1 and fake.asked == []
    assert fake.locked_runs == [("systemctl", "is-active", "tvgw.service"), (doctor.TVGW_APPLY,)]
    assert ("systemctl", "restart", "tvgw.service") not in fake.ran and (
        "systemctl",
        "restart",
        "tvgw",
    ) not in fake.ran


def test_a_stopped_tvgw_service_is_started_never_restarted(lg):
    """A restart of an active tvgw.service runs its stop, which switches the TV's forwarding off."""
    fake = Fake(
        [result(Check("services", False, "down: tvgw")), OK_RUN],
        commands={("systemctl", "is-active", "tvgw.service"): (3, "inactive\n")},
    )
    assert doc(fake, lg, yes=True) == 0
    assert fake.locked_runs == [
        ("systemctl", "is-active", "tvgw.service"),
        ("systemctl", "start", "tvgw.service"),
    ]
    assert not any("restart" in " ".join(c) and "tvgw" in c for c in fake.ran)


@pytest.mark.parametrize(
    ("check", "steps"),
    [
        (
            Check("guard_present", False, "table inet tvgw_guard is not loaded"),
            [("systemctl", "reload-or-restart", "tvgw-guard.service")],
        ),
        (
            Check("adguard_pinned", False, "AdGuard Home may update itself"),
            [("tvgw", "adguard", "service"), ("systemctl", "start", "AdGuardHome"), AGH_JOURNAL],
        ),
        (
            Check("services", False, "down: AdGuardHome"),
            [("tvgw", "adguard", "service"), ("systemctl", "start", "AdGuardHome"), AGH_JOURNAL],
        ),
        (
            Check("services", False, "down: tvgw-analyze.timer"),
            [("systemctl", "enable", "--now", "tvgw-analyze.timer")],
        ),
        (
            Check("doh4_fresh", False, "9.0 days old"),
            [
                ("systemctl", "start", "tvgw-doh-update.service"),
                ("journalctl", "-u", "tvgw-doh-update", "-n", "5", "-o", "cat"),
            ],
        ),
        (Check("store_backup", True, "no backup recorded yet", warn=True), [("tvgw", "backup")]),
        (Check("ingest_fresh", True, "the last ingest ran 3 hours ago", warn=True), [("tvgw", "ingest")]),
    ],
)
def test_each_unit_gets_the_fix_it_tolerates(lg, check, steps):
    fake = Fake([result(check), OK_RUN])
    assert doc(fake, lg, yes=True) == 0
    assert fake.locked_runs == steps


@pytest.mark.parametrize(
    "unit", ["dnsmasq", "nginx", "tvgw-pcap", "tvgw-pcap-headers", "tvgw-flowlog", "tvgw-dnsgate"]
)
def test_dnsmasq_nginx_and_the_recording_units_are_restarted_and_their_journal_shown(lg, unit):
    journal = ("journalctl", "-u", unit, "-n", "5", "-o", "cat")
    fake = Fake(
        [result(Check("services", False, f"down: {unit}")), OK_RUN],
        commands={journal: (0, "started\nDHCPACK(eth0) 10.10.10.17 00:00:5e:00:53:17 tv\nvia 192.0.2.1\n")},
    )
    assert doc(fake, lg, yes=True) == 0
    assert fake.locked_runs == [("systemctl", "restart", unit), journal]
    # the journal's lines are shown with MACs and addresses outside the TV's subnet replaced
    assert "    DHCPACK(eth0) 10.10.10.17 <mac> tv" in fake.said and "    via <address>" in fake.said


def test_several_units_down_get_one_fix_each_and_the_firewall_first(lg):
    fake = Fake(
        [
            result(
                Check("services", False, "down: dnsmasq, tvgw, nginx"),
                Check("tv_route", False, "via nothing"),
            ),
            OK_RUN,
        ]
    )
    assert doc(fake, lg, yes=True) == 0
    starts = [c for c in fake.locked_runs if c[0] != "journalctl"]
    assert starts == [
        ("systemctl", "is-active", "tvgw.service"),
        (doctor.TVGW_APPLY,),  # once, though two findings asked for it
        ("systemctl", "restart", "dnsmasq"),
        ("systemctl", "restart", "nginx"),
    ]


def test_a_unit_without_a_fix_of_its_own_is_explained(lg):
    fake = Fake([result(Check("services", False, "down: someone-else.service"))])
    assert doc(fake, lg, yes=True) == 1
    assert (
        "  The doctor has no fix of its own for someone-else.service: see why it stopped with journalctl -u someone-else.service -n 20."
        in fake.said
    )
    assert fake.lock_taken == 0


def test_the_disk_fix_prunes_the_recordings_and_trims_the_copies(lg):
    fake = Fake(
        [
            result(Check("disk", True, "300 MiB free where the record is kept, under 512 MiB", warn=True)),
            OK_RUN,
        ]
    )
    assert doc(fake, lg, yes=True) == 0
    assert fake.locked_runs == [("tvgw", "prune-pcaps")] and fake.trimmed == 1
    assert "  removed 2 older copies of the record" in fake.said
    read_only = Fake([result(Check("disk", True, "the filesystem of /var/lib/tvgw is read-only", warn=True))])
    doc(read_only, lg, yes=True)
    assert read_only.ran == [] and read_only.trimmed == 0


@pytest.mark.parametrize(
    "name",
    ["uplink_ipv4", "forward_policy", "input_policy", "clock_synced", "tv_paths", "tv_port_neighbours"],
)
def test_explain_only_findings_change_nothing(lg, name):
    fake = Fake([result(Check(name, False, "x"))])
    assert doc(fake, lg, yes=True) == 1
    assert fake.ran == [] and fake.lock_taken == 0
    assert fake.said[-1] == doctor.BYPASS


def held(name: str, detail: str) -> Check:
    """A finding of FAIL level as a new check reports it while it is held at WARN (verify.held)."""
    return Check(name, *verify.held(name, verify.FAIL, detail))


def test_another_firewall_is_explained_with_the_commands_that_open_the_tv_port(lg):
    closed = "1 other forward-hook chain drops by default; 1 of them accepts nothing from the TV's port"
    fake = Fake([result(held("forward_policy", closed))])
    doc(fake, lg)
    assert "    sudo ufw route allow in on eth0 out on wlan0" in fake.said
    assert "    sudo ufw allow in on eth0 proto udp to any port 67" in fake.said
    assert any("ip-forward-no-drop" in line for line in fake.said)
    assert fake.ran == []
    # with the VPN as the uplink, the route opens the tunnel tvgw-apply sends the TV out by
    vpn = Fake(
        [result(held("forward_policy", closed))],
        files={"/proc/sys/net/ipv4/conf/wgpia0/forwarding": "1\n"},
    )
    doctor.main(dataclasses.replace(S, uplink="vpn"), lg, vpn.env())
    assert "    sudo ufw route allow in on eth0 out on wgpia0" in vpn.said
    inp = Fake([result(held("input_policy", "1 other input-hook chain drops by default; ..."))])
    doc(inp, lg)
    assert "    sudo ufw allow in on eth0 proto udp to any port 67" in inp.said
    assert not any("ip-forward-no-drop" in line for line in inp.said)  # Docker's option is about forwarding
    # once promoted, the same finding fails, and is explained the same way
    failed = Fake([result(Check("forward_policy", False, closed))])
    doc(failed, lg)
    assert "    sudo ufw route allow in on eth0 out on wlan0" in failed.said


@pytest.mark.parametrize(
    "name, detail",
    [
        ("forward_policy", "1 other forward-hook chain drops by default; it accepts the TV's port"),
        ("input_policy", "2 other input-hook chains drop by default; each accepts the TV's DHCP and DNS"),
    ],
)
def test_another_firewall_that_lets_the_tv_through_needs_nothing_opened(lg, name, detail):
    fake = Fake([result(Check(name, *verify.held(name, verify.WARN, detail)))])
    assert doc(fake, lg) == 0
    assert "  That firewall lets the TV's traffic through, so there is nothing to open:" in "\n".join(
        fake.said
    )
    assert not any("sudo ufw" in line for line in fake.said)
    assert fake.ran == [] and fake.asked == []


def test_a_ruleset_that_could_not_be_read_still_gets_the_commands(lg):
    fake = Fake([result(Check("forward_policy", True, verify.NO_RULESET, warn=True))])
    doc(fake, lg)
    assert "    sudo ufw route allow in on eth0 out on wlan0" in fake.said


def test_a_lookup_failure_with_the_uplink_down_says_the_internet_is_down(lg):
    fake = Fake(
        [result(Check("resolver_must_allow", False, "us.lgtvsdp.com->no answer"))],
        files={"/sys/class/net/wlan0/carrier": "0\n"},
    )
    assert doc(fake, lg, yes=True) == 1
    assert (
        "  Your internet connection is down: this computer's connection to your router (wlan0) has no link."
        in fake.said
    )
    assert fake.lock_taken == 0  # nothing the doctor can do about it


def test_a_router_that_does_not_answer_is_the_internet_down(lg):
    neigh = ("ip", "-j", "neigh", "show", "dev", "wlan0", "198.51.100.1")
    fake = Fake(
        [result(Check("resolver_rewrite", False, "ngfts.lge.com->None"))],
        commands={neigh: (0, json.dumps([{"dst": "198.51.100.1", "state": ["FAILED"]}]))},
    )
    doc(fake, lg, yes=True)
    assert ("ping", "-c", "1", "-W", "2", "-I", "wlan0", "198.51.100.1") in fake.ran
    assert "  Your internet connection is down: your router does not answer this computer." in fake.said


def test_an_upstream_that_cannot_be_reached_is_the_internet_down(lg):
    curl = ("curl", "--max-time", "5", "-sS", "-o", "/dev/null", "https://1.1.1.1/dns-query")
    fake = Fake(
        [result(Check("resolver_must_allow", False, "x->no answer"))], commands={curl: (28, "timed out")}
    )
    doc(fake, lg, yes=True)
    assert any(
        line.startswith("  Your internet connection is down: this computer cannot reach")
        for line in fake.said
    )


def test_adguard_running_but_silent_while_the_internet_works_is_restarted(lg):
    """The probes reached the router and the encrypted upstream, and AdGuard answered nothing: it serves
    no cache a restart could empty, and `tvgw adguard service` leaves a running AdGuard as it is."""
    fake = Fake(
        [result(Check("resolver_must_allow", False, "x->no answer")), OK_RUN], resolve=lambda name: None
    )
    assert doc(fake, lg, yes=True) == 0
    assert (
        "  AdGuard Home is not answering: the filter did not answer a lookup from this computer." in fake.said
    )
    assert fake.locked_runs == [("systemctl", "restart", "AdGuardHome"), AGH_JOURNAL]


def test_adguard_stopped_is_started_once_for_the_unit_and_the_lookups_and_never_restarted(lg):
    """A stopped AdGuard fails the services check and the lookup checks: one start, no restart."""
    fake = Fake(
        [
            result(
                Check("services", False, "down: AdGuardHome"),
                Check("resolver_must_allow", False, "x->no answer"),
            ),
            OK_RUN,
        ],
        resolve=lambda name: None,
    )
    assert doc(fake, lg, yes=True) == 0
    assert fake.locked_runs == [
        ("tvgw", "adguard", "service"),
        ("systemctl", "start", "AdGuardHome"),
        AGH_JOURNAL,
    ]
    assert not any(c[:2] == ("systemctl", "restart") for c in fake.ran)


def test_a_stopped_adguard_is_started_even_when_its_service_step_fails(lg):
    """Starting a stopped AdGuard cannot hurt, so it follows a `tvgw adguard service` that failed."""
    fake = Fake(
        [result(Check("services", False, "down: AdGuardHome")), OK_RUN],
        commands={("tvgw", "adguard", "service"): (1, "tvgw adguard: cannot read one ExecStart")},
    )
    doc(fake, lg, yes=True)
    assert fake.locked_runs == [
        ("tvgw", "adguard", "service"),
        ("systemctl", "start", "AdGuardHome"),
        AGH_JOURNAL,
    ]
    assert "  it failed (exit 1)" in fake.said


def test_a_dnsgate_warning_is_explained_and_never_applied(lg):
    """The gate's list more than half full needs no fix, and an apply would empty what it has seen."""
    fake = Fake([result(Check("dnsgate", True, "seen4 is 61% full", warn=True))])
    assert doc(fake, lg, yes=True) == 0
    assert fake.locked_runs == [] and fake.lock_taken == 0
    assert "  A warning alone needs no fix: it says the TV is doing something new." in fake.said


def test_each_run_leaves_its_verdict_in_the_status_file(lg):
    """`tvgw status` and the login message then agree with what the doctor last saw."""
    first = result(Check("forwarding", False, "ip_forward=0 (TV offline)"))
    fake = Fake([first, first, OK_RUN])
    assert doc(fake, lg, yes=True) == 0
    assert fake.statuses == [first, OK_RUN]
    explained = Fake([first], tty=False)
    doc(explained, lg)
    assert explained.statuses == [first]


def test_the_blocklist_service_could_not_be_reached(lg):
    url = lg.adguard_filters[0][1]
    head = ("curl", "--max-time", "5", "-sS", "-o", "/dev/null", "-I", url)
    fake = Fake([result(Check("list_sentinels", False, "list not in force: x"))], commands={head: (6, "")})
    doc(fake, lg, yes=True)
    assert (
        "  The blocklist service could not be reached: the filter keeps the lists it has and downloads them again on its own."
        in fake.said
    )
    assert fake.lock_taken == 0


def test_with_every_probe_passing_a_lookup_fix_writes_the_filters_settings_again(lg):
    fake = Fake([result(Check("resolver_rewrite", False, "ngfts.lge.com->['0.0.0.0']")), OK_RUN])
    assert doc(fake, lg, yes=True) == 0
    assert fake.locked_runs == [("tvgw", "adguard", "apply")]


def test_a_transient_must_allow_warning_needs_nothing(lg):
    fake = Fake([result(Check("resolver_must_allow", True, "transient: x->empty answer; ...", warn=True))])
    assert doc(fake, lg, yes=True) == 0
    assert fake.ran == [] and any("a one-off" in line for line in fake.said)


def test_no_terminal_and_no_yes_explains_only(lg):
    fake = Fake([result(Check("forwarding", False, "ip_forward=0"))], tty=False)
    assert doc(fake, lg) == 1
    assert fake.asked == [] and fake.ran == [] and fake.lock_taken == 0
    assert (
        "Nothing was changed. To let the doctor do the fixes above, run: sudo tvgw doctor --fix --yes"
        in fake.said
    )
    fix_only = Fake([result(Check("forwarding", False, "ip_forward=0"))], tty=False)
    assert doc(fix_only, lg, fix=True) == 1  # --fix still asks, and without a terminal the answer is no
    assert fix_only.ran == []


def test_fix_asks_once_for_everything(lg):
    fake = Fake(
        [result(Check("forwarding", False, "x"), Check("services", False, "down: nginx")), OK_RUN],
        answers=[True],
    )
    assert doc(fake, lg, fix=True) == 0
    assert fake.asked == ["Do the 2 fixes above now?"]
    assert (doctor.TVGW_APPLY,) in fake.locked_runs and ("systemctl", "restart", "nginx") in fake.locked_runs


def test_a_no_changes_nothing(lg):
    fake = Fake([result(Check("forwarding", False, "x"))], answers=[False])
    assert doc(fake, lg) == 1
    assert fake.ran == [] and fake.lock_taken == 0 and "Nothing was changed." in fake.said


def test_under_the_lock_it_checks_again_and_skips_what_a_deploy_fixed(lg):
    """A CI deploy held the lock and fixed the firewall meanwhile: nothing is run twice."""
    fixed = result(Check("forwarding", True))
    fake = Fake([result(Check("forwarding", False, "x")), fixed])
    assert doc(fake, lg, yes=True) == 0
    assert fake.locked_runs == [] and fake.checks == 3
    assert "Every chosen fix is already done: the checks pass now." in fake.said


def test_a_lock_held_by_another_install_changes_nothing(lg):
    from tvgw import setup

    fake = Fake([result(Check("forwarding", False, "x"))])
    fake.lock_error = setup.SetupError("another install is running (waited 10 minutes)")
    assert doc(fake, lg, yes=True) == 1
    assert fake.ran == []
    assert (
        "tvgw doctor: another install is running (waited 10 minutes); nothing was changed. Try again when it has finished."
        in fake.said
    )
    assert fake.said[-1] == doctor.BYPASS


def test_a_fix_that_raises_is_said_and_the_rest_still_run(lg):
    fake = Fake(
        [
            result(
                Check("disk", True, "1.5 GiB free where the record is kept, under 2.0 GiB", warn=True),
                Check("forwarding", False, "x"),
            ),
            OK_RUN,
        ]
    )

    def denied():
        raise PermissionError(13, "Permission denied")

    fake.trim = denied
    assert doc(fake, lg, yes=True) == 0
    assert "  the older copies could not be removed: Permission denied" in fake.said
    assert (doctor.TVGW_APPLY,) in fake.locked_runs and ("tvgw", "prune-pcaps") in fake.locked_runs


def test_what_still_fails_after_the_fixes_is_named_and_settling_checks_are_waited_on(lg):
    after = result(Check("services", False, "down: nginx"))
    fake = Fake([result(Check("services", False, "down: nginx")), after, after])
    assert doc(fake, lg, yes=True) == 1
    assert "Still failing: services." in fake.said
    assert any(line.startswith("Some of these can take a few minutes") for line in fake.said)


def test_a_failing_step_stops_its_fix_and_is_said(lg):
    fake = Fake(
        [result(Check("doh4_loaded", False, "1 addresses")), OK_RUN],
        commands={("systemctl", "start", "tvgw-doh-update.service"): (1, "Job failed")},
    )
    doc(fake, lg, yes=True)
    assert "  it failed (exit 1)" in fake.said
    # the journal is shown whatever the start did: it says why
    assert fake.locked_runs[-1][0] == "journalctl"


def test_every_check_with_a_fix_names_one_the_tests_cover():
    """APPLY_CHECKS are real checks or W0's reply route, and their fix's command is the installed script."""
    known = set(verify.PLAIN) | {"gw_reply_route"}
    assert known >= doctor.APPLY_CHECKS
    assert doctor.TVGW_APPLY == "/usr/local/sbin/tvgw-apply"


def test_redact_keeps_the_tv_subnet_and_replaces_the_rest():
    line = "DHCPACK(eth0) 10.10.10.17 00:00:5e:00:53:17 from 198.51.100.4 to 10.20.30.40 00-00-5E-00-53-AB"
    assert (
        doctor.redact(line, "10.10.10.0/24")
        == "DHCPACK(eth0) 10.10.10.17 <mac> from <address> to <address> <mac>"
    )
    assert doctor.redact("version 1.2.3.4", "garbage") == "version <address>"


def test_redact_replaces_ipv6_addresses_and_interface_names_that_carry_a_mac():
    line = (
        "20:18:01 RTR-SOLICIT(enx00005e005317) fe80::200:5eff:fe00:5317%wlan0 via 2001:db8::1, "
        "upstream [2001:db8:0:1::53]:853 ::1 and :: at 12:34"
    )
    assert doctor.redact(line, "10.10.10.0/24") == (
        "20:18:01 RTR-SOLICIT(usb-ethernet) <address> via <address>, "
        "upstream [<address>]:853 <address> and <address> at 12:34"
    )
    # a MAC is a MAC first, never half an IPv6 address; a time or a version is neither
    assert doctor.redact("00:00:5e:00:53:17 at 10:40:05 v0.107.79", "10.10.10.0/24") == (
        "<mac> at 10:40:05 v0.107.79"
    )


def test_a_fixs_output_goes_through_the_gateways_scrubber_before_redact(lg):
    """The lines a fix prints (a journal) can carry the host name, the TV's name or the Wi-Fi's beside
    the addresses redact() takes: with the gateway's scrubber on the Env (live_env builds one), those go
    too, so the doctor's output may stand in a public CI log or an issue."""
    from tvgw.scrub import Scrubber

    fake = Fake([result(Check("services", False, "down: dnsmasq")), OK_RUN], tty=True, answers=[True])
    fake.commands[("journalctl", "-u", "dnsmasq", "-n", "5", "-o", "cat")] = (
        0,
        "DHCPACK(eth0) 10.10.10.17 00:00:5e:00:53:17 living-room-tv on gateway-under-test.home-isp.example"
        " via 198.51.100.4; wifi example-wifi\n",
    )
    env = dataclasses.replace(
        fake.env(),
        scrub=Scrubber(
            S.tv_net,
            hostname="gateway-under-test",
            tv_name="living-room-tv",
            ssids=["example-wifi"],
            domains=["home-isp.example"],
        ),
    )
    assert doctor.main(S, lg, env) == 0
    shown = next(line for line in fake.said if "DHCPACK" in line)
    assert shown.strip() == (
        "DHCPACK(eth0) 10.10.10.17 <mac> <tv name> on <this computer>.<domain> via <lan address>; wifi <wifi name>"
    )
    for word in ("living-room-tv", "gateway-under-test", "home-isp", "example-wifi", "198.51.100.4"):
        assert word not in fake.text


def test_the_live_env_carries_this_gateways_scrubber(monkeypatch, lg):
    marker = object()
    monkeypatch.setattr(doctor.scrub, "scrub_for", lambda s: marker)
    assert doctor.live_env(S, lg, "/etc/tvgw/tvgw.conf").scrub is marker


def test_the_live_env_runs_this_tvgw_with_the_same_settings_file(monkeypatch, lg):
    seen = []

    class Done:
        returncode, stdout, stderr = 0, "out\n", ""

    monkeypatch.setattr(doctor.subprocess, "run", lambda argv, **kw: seen.append(argv) or Done())
    env = doctor.live_env(S, lg, "/etc/tvgw/tvgw.conf")
    assert env.run(["tvgw", "backup"]) == (0, "out\n")
    assert seen[-1][1:] == ["-m", "tvgw", "--conf", "/etc/tvgw/tvgw.conf", "backup"]
    assert env.run(["systemctl", "restart", "nginx"]) == (0, "out\n") and seen[-1] == [
        "systemctl",
        "restart",
        "nginx",
    ]

    def missing(argv, **kw):
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(doctor.subprocess, "run", missing)
    assert env.run(["curl", "x"]) == (127, "")


def test_the_cli_runs_the_doctor_as_root_only(monkeypatch, tmp_path, capsys, lg):
    conf = tmp_path / "tvgw.conf"
    conf.write_text(f"STATE_DIR={tmp_path}\nDB_PATH={tmp_path / 't.db'}\n")
    monkeypatch.setattr(doctor.os, "geteuid", lambda: 1000)
    assert cli.main(["--conf", str(conf), "doctor"]) == 1
    assert (
        capsys.readouterr().out == f"tvgw doctor: run it as root, with: sudo tvgw doctor\n{doctor.BYPASS}\n"
    )
    seen = {}

    def fake_main(s, prof, env, fix=False, yes=False):
        seen.update(fix=fix, yes=yes, state=s.state_dir, profile=prof.name)
        return 0

    monkeypatch.setattr(doctor, "main", fake_main)
    assert cli.main(["--conf", str(conf), "doctor", "--fix", "--yes"]) == 0
    assert seen == {"fix": True, "yes": True, "state": str(tmp_path), "profile": "lg-webos"}


def test_the_doctors_settings_reach_its_probes(lg):
    """A second site's uplink and upstreams are the ones probed."""
    s = dataclasses.replace(S, wan_if="eth1", dns_upstreams="https://192.0.2.53/dns-query")
    curl = ("curl", "--max-time", "5", "-sS", "-o", "/dev/null", "https://192.0.2.53/dns-query")
    fake = Fake(
        [result(Check("resolver_rewrite", False, "x"))],
        files={"/sys/class/net/eth1/carrier": "1\n"},
        commands={curl: (7, "")},
    )
    doctor.main(s, lg, fake.env(), yes=True)
    assert ("ip", "-j", "route", "show", "default", "dev", "eth1") in fake.ran and curl in fake.ran
