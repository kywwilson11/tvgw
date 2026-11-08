"""(ports) The clock port in tvgw-apply (design decision 71), against the stub commands of test_apply.py.

CLOCK_PORT=profile (the default) builds what the profile's [firewall] ntp says, read through `tvgw profile
--firewall`; any, resolved and none say it outright. none closes UDP 123 in tv_out, ahead of the odd-port
rules, unless the NTP count holds an address (the TV sent NTP within its ten days); resolved is held back
on a live gateway (CLOCK_RESOLVED_SUPPORTED=no), and a copy with the line set to yes builds it in the gate's
table beside the in-path filler's set. What the kernel makes of the rules is the namespace tier's
(tests/virtual/test_virtual_clock.py); what the script asks of nft, and what it records, is checked here."""

from __future__ import annotations

import shutil

import pytest
import test_apply
from test_apply import CONF, STUBS, chain, ruleset, run_apply
from test_apply_check import checked, nft_calls, run_check

from tvgw import config, verify

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")

APPLY = test_apply.APPLY
CLOSE_LOG = 'udp dport 123 limit rate 6/minute log prefix "tvgw-ntp: "'
CLOSE = 'udp dport 123 counter reject comment "clock port: closed, NTP to no server"'
RESOLVED = "clock port: only to an address a lookup returned"
ODD_LOG = (
    'meta l4proto { tcp, udp } th dport != { 80, 123, 443 } limit rate 6/minute log prefix "tvgw-oddport: "'
)
# nft as test_apply's stub, whose NTP count holds two servers the TV asked
COUNTED = STUBS["nft"].replace(
    'case "$*" in\n',
    'case "$*" in\n"list set inet tvgw_ntp ntp4") printf \'table inet tvgw_ntp {\\n\\tset ntp4 {\\n'
    "\\t\\ttype ipv4_addr\\n\\t\\tsize 1024\\n\\t\\tflags dynamic,timeout\\n\\t\\ttimeout 10d\\n"
    "\\t\\telements = { 203.0.113.10 counter packets 2 bytes 152 expires 9d23h, 203.0.113.53 counter packets 1"
    " bytes 76 expires 9d }\\n\\t}\\n}\\n' ;;\n",
    1,
)


def tvgw_says(text: str, rc: int = 0) -> str:
    """A `tvgw` that answers `profile --firewall` with `text`, and records that it was asked."""
    return f"#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$STUB_DIR/tvgw.calls\"\nprintf '%s' '{text}'\nexit {rc}\n"


def applied(tmp_path) -> dict[str, str]:
    return config.parse_conf((tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8"))


def apply_with(tmp_path, monkeypatch, conf: str, tvgw: str | None = None, nft: str | None = None, text=None):
    """The apply with `tvgw` (a stub's body) in place of /usr/local/bin/tvgw, and `nft` in place of the
    stub nft; `text` is a copy of the script."""
    script = (text or APPLY).replace("/usr/local/bin/tvgw", f"{tmp_path}/bin/tvgw")
    monkeypatch.setattr(test_apply, "APPLY", script)
    stubs = {**({"tvgw": tvgw} if tvgw else {}), **({"nft": nft} if nft else {})}
    return run_apply(tmp_path, conf=conf, stubs=stubs)


def supported(text: str = APPLY) -> str:
    assert text.count("\nCLOCK_RESOLVED_SUPPORTED=no\n") == 1
    return text.replace("\nCLOCK_RESOLVED_SUPPORTED=no\n", "\nCLOCK_RESOLVED_SUPPORTED=yes\n")


# ---- the defaults change nothing -------------------------------------------------------------------------


def test_without_the_key_the_port_is_open_and_the_record_says_why(tmp_path):
    out = run_apply(tmp_path)
    assert out.returncode == 0, out.stderr
    assert "123" not in " ".join(line for line in chain(ruleset(tmp_path), "tv_out") if "dport 123" in line)
    assert "clock port" not in ruleset(tmp_path)
    got = applied(tmp_path)
    assert (got["CLOCK_PORT"], got["CLOCK_PORT_PROFILE"], got["CLOCK_PORT_USED"]) == (
        "profile",
        "unread",
        "any",
    )
    # no tvgw to ask: the apply says so, and leaves the port as it was before the key existed
    assert "the profile's clock port rule could not be read" in out.stderr


def test_any_and_a_profile_that_says_any_render_byte_for_byte_what_no_key_renders(tmp_path, monkeypatch):
    assert run_apply(tmp_path / "none").returncode == 0
    assert run_apply(tmp_path / "any", conf=CONF + "CLOCK_PORT=any\n").returncode == 0
    out = apply_with(tmp_path / "profile", monkeypatch, CONF, tvgw=tvgw_says("ntp=any\n"))
    assert out.returncode == 0 and "could not be read" not in out.stderr
    scripts = [test_apply.scripts(tmp_path / side) for side in ("none", "any", "profile")]
    assert scripts[0] == scripts[1] == scripts[2]
    assert applied(tmp_path / "profile")["CLOCK_PORT_PROFILE"] == "any"


# ---- none ------------------------------------------------------------------------------------------------


def test_none_closes_the_port_ahead_of_the_odd_port_rules_with_a_count_and_a_sample(tmp_path):
    out = run_apply(tmp_path, conf=CONF + "CLOCK_PORT=none\n")
    assert out.returncode == 0, out.stderr
    tv_out = chain(ruleset(tmp_path), "tv_out")
    at = tv_out.index(CLOSE)
    assert tv_out[at - 1] == CLOSE_LOG and tv_out[at + 1].startswith(ODD_LOG)
    assert tv_out.index('ip daddr 156.147.69.32 tcp dport 8080 counter log prefix "tvgw-lg8080: " accept '
                        'comment "LG firmware fallback path"') < at  # fmt: skip
    got = applied(tmp_path)
    assert (got["CLOCK_PORT"], got["CLOCK_PORT_PROFILE"], got["CLOCK_PORT_USED"]) == ("none", "", "none")
    assert "list set inet tvgw_ntp ntp4" in nft_calls(tmp_path)  # the count was asked first
    assert verify.apply_settings(CONF + "CLOCK_PORT=none\n")["CLOCK_PORT"] == "none"


def test_none_stays_open_while_the_ntp_count_holds_a_server(tmp_path):
    """The TV sent NTP to two servers within the count's ten days: closing the port would cut its clock
    off, so the apply builds it open, says so, and records that it did."""
    out = run_apply(tmp_path, conf=CONF + "CLOCK_PORT=none\n", stubs={"nft": COUNTED})
    assert out.returncode == 0, out.stderr
    assert "clock port" not in ruleset(tmp_path)
    assert "the clock port stays open" in out.stderr and "2 server(s)" in out.stderr
    assert applied(tmp_path)["CLOCK_PORT_USED"] == "any"


def test_the_probes_twin_carries_the_closed_port_and_not_its_count(tmp_path):
    out = run_apply(tmp_path, conf=CONF + "CLOCK_PORT=none\nTV_PROBE=on\n")
    assert out.returncode == 0, out.stderr
    loaded = test_apply.scripts(tmp_path)[0]
    assert "add rule inet tvgw probe_out udp dport 123 reject\n" in loaded
    assert "tvgw-ntp" not in "".join(ln for ln in loaded.splitlines(True) if " probe_" in ln)


def test_the_check_renders_none_without_asking_the_live_count(tmp_path):
    out = run_check(tmp_path, conf=CONF + "CLOCK_PORT=none\n")
    assert out.returncode == 0, out.stderr
    assert CLOSE in checked(tmp_path)[0]
    assert not [c for c in nft_calls(tmp_path) if c.startswith("list set")]


# ---- the profile -----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("said", "rc", "profile", "used"),
    [
        ("ntp=none\n", 0, "none", "none"),
        ("ntp=any\n", 0, "any", "any"),
        ("ntp=resolved\n", 0, "resolved", "any"),  # held back on a live gateway
        ("ntp=sideways\n", 0, "unread", "any"),
        ("", 0, "unread", "any"),
        ("ntp=none\n", 1, "unread", "any"),  # a tvgw that fails is no answer, whatever it printed
        ("tvgw: settings file refused\n", 1, "unread", "any"),
    ],
)
def test_profile_builds_what_the_profile_says_and_any_when_it_cannot_be_read(
    tmp_path, monkeypatch, said, rc, profile, used
):
    out = apply_with(tmp_path, monkeypatch, CONF, tvgw=tvgw_says(said, rc))
    assert out.returncode == 0, out.stderr
    got = applied(tmp_path)
    assert (got["CLOCK_PORT_PROFILE"], got["CLOCK_PORT_USED"]) == (profile, used)
    assert (CLOSE in ruleset(tmp_path)) == (used == "none")
    assert ("could not be read" in out.stderr) == (profile == "unread")
    assert (tmp_path / "stub" / "tvgw.calls").read_text(encoding="utf-8").splitlines() == [
        "profile --firewall"
    ]


def test_a_key_that_says_otherwise_never_asks_the_profile(tmp_path, monkeypatch):
    out = apply_with(tmp_path, monkeypatch, CONF + "CLOCK_PORT=any\n", tvgw=tvgw_says("ntp=none\n"))
    assert out.returncode == 0 and not (tmp_path / "stub" / "tvgw.calls").exists()
    assert "clock port" not in ruleset(tmp_path)


# ---- resolved --------------------------------------------------------------------------------------------


def test_resolved_is_held_back_on_a_live_gateway(tmp_path):
    out = run_apply(tmp_path, conf=CONF + "CLOCK_PORT=resolved\nDNSGATE_FILL=inpath\n")
    assert out.returncode == 0, out.stderr
    assert "not supported on a live gateway yet" in out.stderr
    assert (
        RESOLVED not in "".join(test_apply.scripts(tmp_path))
        and applied(tmp_path)["CLOCK_PORT_USED"] == "any"
    )


def test_where_resolved_is_supported_it_reads_both_sets_and_keeps_a_server_while_it_is_asked(
    tmp_path, monkeypatch
):
    out = apply_with(
        tmp_path, monkeypatch, CONF + "CLOCK_PORT=resolved\nDNSGATE_FILL=inpath\n", text=supported()
    )
    assert out.returncode == 0, out.stderr
    last = test_apply.scripts(tmp_path)[-1]  # the last load: after the in-path block that makes its set
    # it stands on its own, as --check hands it to nft -c alone: the table and both sets named again,
    # exactly as the gate's load and the in-path load write them, so the add changes nothing that is there
    gate_set = "add set inet tvgw_gate resolved4 { type ipv4_addr; flags timeout; size 65536; }"
    inpath_set = "add set inet tvgw_gate resolved4_inpath { type ipv4_addr; flags timeout; size 65536; }"
    assert last.startswith(f"add table inet tvgw_gate\n{gate_set}\n{inpath_set}\n")
    assert APPLY.count(gate_set) == APPLY.count(inpath_set) == 2  # the load that makes each, and this one
    assert "add set inet tvgw_gate ntp_ok4 { type ipv4_addr; flags dynamic, timeout; timeout 10d;" in last
    assert (
        "add chain inet tvgw_gate clock { type filter hook forward priority filter - 3; policy accept; }"
        in last
    )
    rules = [ln for ln in last.splitlines() if ln.startswith("add rule inet tvgw_gate clock ")]
    assert len(rules) == 5 and all('iifname "eth0" ip saddr 10.10.10.0/24 udp dport 123 ' in r for r in rules)
    assert rules[-1].endswith(
        f'ip daddr != @ntp_ok4 ip daddr != @resolved4 ip daddr != @resolved4_inpath counter reject comment "{RESOLVED}"'
    )
    assert "update @ntp_ok4 { ip daddr }" in rules[2] and "@ntp_ok4" in rules[2].split("update")[0]
    assert "clock port" not in ruleset(tmp_path)  # nothing in tv_out: the probe's port does not see it
    assert applied(tmp_path)["CLOCK_PORT_USED"] == "resolved"


@pytest.mark.parametrize("conf", ["DNSGATE_FILL=passive\n", "DNSGATE=off\nDNSGATE_FILL=inpath\n"])
def test_resolved_without_the_in_path_set_falls_back_to_any(tmp_path, monkeypatch, conf):
    out = apply_with(tmp_path, monkeypatch, CONF + "CLOCK_PORT=resolved\n" + conf, text=supported())
    assert out.returncode == 0, out.stderr
    assert "needs DNSGATE=count and DNSGATE_FILL=inpath" in out.stderr
    assert (
        RESOLVED not in "".join(test_apply.scripts(tmp_path))
        and applied(tmp_path)["CLOCK_PORT_USED"] == "any"
    )


def test_leaving_resolved_takes_its_chain_and_its_set_while_the_queue_is_quiet(tmp_path, monkeypatch):
    """The stub says an earlier apply left the in-path half: its cleanup takes the clock chain too (a hook),
    flushed and deleted in one transaction, and its set unless this apply builds resolved again."""
    run_apply(tmp_path / "any", conf=CONF + "DNSGATE_FILL=inpath\n")
    calls = nft_calls(tmp_path / "any")
    gone = calls.index("flush chain inet tvgw_gate clock; delete chain inet tvgw_gate clock")
    assert calls[gone + 1] == "delete set inet tvgw_gate ntp_ok4" and gone > calls.index(
        "delete chain inet tvgw_gate answers"
    )
    assert gone < calls.index("-f -")
    apply_with(
        tmp_path / "again", monkeypatch, CONF + "CLOCK_PORT=resolved\nDNSGATE_FILL=inpath\n", text=supported()
    )
    again = nft_calls(tmp_path / "again")
    assert "flush chain inet tvgw_gate clock; delete chain inet tvgw_gate clock" in again
    assert "delete set inet tvgw_gate ntp_ok4" not in again  # its servers stay admitted


# ---- the switch itself -----------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["None", "closed", "yes", "PROFILE"])
def test_a_near_miss_stops_the_apply_before_anything_is_loaded(tmp_path, value):
    out = run_apply(tmp_path, conf=CONF + f"CLOCK_PORT={value}\n")
    assert out.returncode == 1 and "CLOCK_PORT must be profile, any, resolved or none" in out.stderr
    assert test_apply.scripts(tmp_path) == []
    with pytest.raises(ValueError, match="CLOCK_PORT"):
        config.check_conf(CONF + f"CLOCK_PORT={value}\n")


def test_the_key_is_one_verify_compares_and_its_records_are_not():
    assert "CLOCK_PORT" in verify.APPLY_KEYS
    assert "CLOCK_PORT_USED" not in verify.APPLY_KEYS and "CLOCK_PORT_PROFILE" not in verify.APPLY_KEYS
    assert config.CHOICES["CLOCK_PORT"][0] == config.Settings().clock_port == "profile"
