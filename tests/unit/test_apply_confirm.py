"""(probe) tvgw-apply with TV_PROBE and APPLY_CONFIRM, against the stub commands of test_apply.py.

What the kernel makes of the probe's rules, and whether a restore puts a working path back, is the
namespace tier's to say (tests/virtual/test_virtual_probe.py). Here: with the defaults the script hands
nft what the script before the probe handed it, byte for byte; the probe's rules are the TV's own, minus what
records; nothing about the probe can stop an apply; and the confirmation decides as design decision 65
says, with a stub in place of `tvgw probe` saying what the probe saw."""

import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import test_apply
from conftest import ROOT
from test_apply import CONF, STUBS, chain, ruleset, run_apply, scripts

from tvgw import config, ledger, probe

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")

APPLY = (ROOT / "deploy" / "nftables" / "tvgw-apply").read_text(encoding="utf-8")
BEFORE = (
    Path(__file__).with_name("tvgw-apply-before-probe").read_text(encoding="utf-8")
)  # the script before the probe: deploy/nftables/tvgw-apply as main had it the day this landed (b6c9712)
ON = CONF + "TV_PROBE=on\n"
MAC = "aa:bb:cc:00:11:22"  # a placeholder, not any device's
# `tvgw probe --across DIR` as the apply sees it: the verdict before (PRE), then, once the apply says go,
# the verdict after (POST); an empty PRE is a probe that dies without a word. A plain `tvgw probe` is the
# look after a restore, and exits as AGAIN says.
TVGW = """#!/bin/sh
printf '%s\\n' "$*" >>"$STUB_DIR/tvgw.calls"
if [ "$1 $2" = "probe --across" ]; then
	[ -n "$PRE" ] || exit 4
	printf '%s\\n{}\\n' "$PRE" >"$3/pre"
	n=0
	while [ ! -e "$3/go" ] && [ ! -e "$3/abort" ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
	[ -e "$3/go" ] || exit 4
	[ -z "$POST" ] || printf '%s\\n{}\\n' "$POST" >"$3/post"
	exit 0
fi
exit "${AGAIN:-0}"
"""
EXTRA = {
    "tvgw": TVGW,
    "timeout": '#!/bin/sh\nwhile [ "${1#-}" != "$1" ]; do shift 2; done\nshift\nexec "$@"\n',  # -k N SECONDS cmd
    "setsid": '#!/bin/sh\nprintf \'%s\\n\' "$*" >>"$STUB_DIR/setsid.calls"\n',  # the detached restore, recorded
    "systemctl": "#!/bin/sh\nexit 0\n",
}


# nft as test_apply's stub, which also says which tables stand and lists the gate's
CONFIRM_NFT = STUBS["nft"].replace(
    'case "$*" in\n',
    'case "$*" in\n"list tables") [ -z "${NFT_TABLES_FAIL:-}" ] || exit 1; printf \'table inet tvgw\\ntable inet tvgw_gate\\n\' ;;\n'
    "\"-s list table inet tvgw_gate\") printf 'table inet tvgw_gate {\\n}\\n' ;;\n",
    1,
)
LIVE = tuple(
    k for k in test_apply.PROC if k != "net/ipv4/conf/eth0/forwarding"
)  # that one is "1": the TV's port forwards


def run_confirm(
    tmp_path,
    conf: str,
    pre: str = "pass -",
    post: str = "pass -",
    again: int = 0,
    more=None,
    last: str | None = "pass",
    age: int = 60,
    revert: bool = True,
    text: str | None = None,
):
    """The apply with its `tvgw` a stub that says `pre` before and `post` after, on a gateway whose last
    probe, `age` seconds ago, said `last` (None: no probe has run) and whose TV port forwards. `revert`:
    a copy of the script in which a revert is supported, as the namespace tier runs it."""
    text = (text or APPLY).replace("/usr/local/bin/tvgw", f"{tmp_path}/bin/tvgw")
    if revert:
        assert text.count("\nREVERT_SUPPORTED=no\n") == 1
        text = text.replace("\nREVERT_SUPPORTED=no\n", "\nREVERT_SUPPORTED=yes\n")
    old, test_apply.APPLY = test_apply.APPLY, text
    for d in ("bin", "stub", "run/tvgw", "proc/sys/net/ipv4/conf/eth0"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    (tmp_path / "proc/sys/net/ipv4/conf/eth0/forwarding").write_text("1\n", encoding="utf-8")
    if last is not None:
        # the script's own clock (`date`), not Python's, which the unit suite's conftest holds still
        now = int(subprocess.check_output(["date", "+%s"], text=True))
        (tmp_path / "run/tvgw/probe.last").write_text(f"{now - age} {last} -\n", encoding="utf-8")
    stubs = {**EXTRA, "nft": CONFIRM_NFT, **(more or {})}
    env = {"PRE": pre, "POST": post, "AGAIN": str(again)}
    try:
        wrapped = {
            name: body.replace(
                "#!/bin/sh\n", "#!/bin/sh\n" + "".join(f"{k}='{v}'\n" for k, v in env.items()), 1
            )
            if name == "tvgw"
            else body
            for name, body in stubs.items()
        }
        return run_apply(tmp_path, conf=conf, proc=LIVE, stubs=wrapped)
    finally:
        test_apply.APPLY = old


def spool(tmp_path) -> list[list[str]]:
    path = tmp_path / "state" / "changes.spool"
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    return [line.split("\t")[1:] for line in lines]


def nft_calls(tmp_path) -> list[str]:
    return (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()


def probe_commands(tmp_path) -> list[str]:
    """The commands the apply added to the inet table's transaction for the probe."""
    return [
        ln for ln in ruleset(tmp_path).splitlines() if re.match(r"(add|insert) (chain|rule) inet tvgw ", ln)
    ]


# ---- with the defaults nothing changes ------------------------------------------------------------------


@pytest.mark.parametrize(
    "conf",
    [
        CONF,
        CONF + f"TV_MAC={MAC}\nTV_IP=10.10.10.17\n",
        "UPLINK=vpn\nBLOCK_QUIC=no\nSTRICT_PORTS=yes\n",
        CONF + "CAPTURE_MODE=headers\nDNSGATE=off\nADTECH_PORT_WALL=no\n",
        CONF + "PROFILE=generic-tv\nWAN_GW_MODE=auto\n",
        CONF + "TV_PROBE=off\nAPPLY_CONFIRM=off\nTV_PROBE_IP=10.10.10.99\n",
    ],
)
def test_with_the_probe_off_every_ruleset_is_byte_for_byte_what_the_script_before_it_loaded(
    tmp_path, monkeypatch, conf
):
    """The script before the probe, kept verbatim beside this file, and today's, run on the same settings: every
    script nft is fed, every command, every routing call and the ledger's line are the same. Only
    settings.applied differs, by the two keys verify now compares."""
    new = run_apply(tmp_path / "new", conf=conf)
    monkeypatch.setattr(test_apply, "APPLY", BEFORE)
    old = run_apply(tmp_path / "old", conf=conf.replace("TV_PROBE", "#").replace("APPLY_CONFIRM", "#"))
    assert (new.returncode, old.returncode) == (0, 0), new.stderr + old.stderr
    assert scripts(tmp_path / "new") == scripts(tmp_path / "old")
    assert new.stdout == old.stdout
    for name in ("nft.calls", "ip.calls"):
        a, b = ((tmp_path / side / "stub" / name).read_text(encoding="utf-8") for side in ("new", "old"))
        assert a.replace(str(tmp_path / "new"), "") == b.replace(str(tmp_path / "old"), ""), name
    assert [row[:1] for row in spool(tmp_path / "new")] == [["apply"]]
    assert not (tmp_path / "new" / "stub" / "tvgw.calls").exists()
    used = dict(
        ln.split("=", 1)
        for ln in (tmp_path / "new" / "run" / "tvgw" / "settings.applied")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    was = (tmp_path / "old" / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
    assert {k: v for k, v in used.items() if not k.startswith("TV_PROBE")} == dict(
        ln.split("=", 1) for ln in was.splitlines()
    )


@pytest.mark.parametrize(("key", "value"), [("TV_PROBE", "On"), ("TV_PROBE", "yes"), ("APPLY_CONFIRM", "on")])
def test_a_near_miss_of_either_switch_stops_the_apply_before_anything_is_loaded(tmp_path, key, value):
    out = run_apply(tmp_path, conf=CONF + f"{key}={value}\n")
    assert out.returncode == 1 and f"{key} must be" in out.stderr
    assert scripts(tmp_path) == []
    with pytest.raises(ValueError, match=key):
        config.check_conf(CONF + f"{key}={value}\n")


# ---- the probe's rules ---------------------------------------------------------------------------------


def twin(lines: list[str]) -> list[str]:
    """What the script should make of a chain's lines, worked out here in Python: the comment lines, the
    counters, the logs and the comments gone, the TV's port renamed, and what is left without a verdict or
    a change left out."""
    out = []
    for line in lines:
        if line.startswith(("#", "type ")) or 'comment "TV source is not the TV"' in line:
            continue
        line = line.replace('iifname "eth0"', 'iifname "tvgw-probe"')
        line = re.sub(r' comment "[^"]*"', "", line)
        line = re.sub(r' log prefix "[^"]*"', "", line)
        line = " ".join(w for w in line.split() if w != "counter")
        if re.search(r"(^| )(accept|drop|reject|jump|dnat|masquerade|set)( |$)", line):
            out.append(line)
    return out


@pytest.mark.parametrize(
    "conf",
    [
        ON,
        ON + f"TV_MAC={MAC}\nTV_IP=10.10.10.17\n",
        "TV_PROBE=on\nUPLINK=vpn\nBLOCK_QUIC=no\nSTRICT_PORTS=yes\n",
        ON + "ADTECH_PORT_WALL=no\nPROFILE=generic-tv\n",
    ],
)
def test_the_probes_chains_are_the_tvs_own_rules_without_what_records(tmp_path, conf):
    """Each probe chain is the twin of the TV's chain as this apply rendered it: the same rules in the
    same order. No rule of the probe's has a counter, a log or a comment, so it moves no number the brief
    reads and writes no sample the ingest reads; the TV's pin is not copied, and the probe's own stands
    first in the two chains its packets enter by."""
    out = run_apply(tmp_path, conf=conf)
    assert out.returncode == 0, out.stderr
    text, cmds = ruleset(tmp_path), probe_commands(tmp_path)
    assert not [c for c in cmds if re.search(r"\b(counter|log|comment|nflog)\b", c)]

    def rules(name: str) -> list[str]:
        return [c.removeprefix(f"add rule inet tvgw {name} ") for c in cmds if f" inet tvgw {name} " in c]

    pin = 'iifname "tvgw-probe" ip saddr != 10.10.10.30 drop'
    inp, fwd = chain(text, "input"), chain(text, "forward")
    assert rules("probe_input") == [pin, *twin(inp[inp.index('iifname != "eth0" accept') + 1 :])]
    after = fwd.index('iifname != "eth0" oifname != "eth0" accept') + 1
    assert rules("probe_fwd") == [
        pin,
        *(r.replace("jump tv_out", "jump probe_out") for r in twin(fwd[after:])),
    ]
    assert rules("probe_out") == twin(chain(text, "tv_out"))
    assert rules("probe_input")[-1] == rules("probe_fwd")[-1] == "drop"  # nothing falls back to an accept
    assert not [r for r in rules("probe_fwd") if "10.10.10.17" in r]  # the TV's pin stays the TV's
    hooks = [c for c in cmds if c.startswith("insert rule")]
    assert hooks[:3] == [
        'insert rule inet tvgw input iifname "tvgw-probe" jump probe_input',
        'insert rule inet tvgw forward oifname "tvgw-probe" jump probe_fwd',
        'insert rule inet tvgw forward iifname "tvgw-probe" jump probe_fwd',
    ]
    for name in ("pre_mangle", "pre_nat", "post_nat"):
        mine = [c.removeprefix(f"insert rule inet tvgw {name} ") for c in hooks if f" tvgw {name} " in c]
        # each goes to the head of its chain, so they are written last first and stand in the TV's order
        assert mine == list(reversed(twin([ln for ln in chain(text, name) if 'iifname "eth0"' in ln]))), name
    # no twin of what records: the flow log's events, and the gate and the capture in their own tables
    assert not [c for c in cmds if "ct event" in c or "ct_events" in c]
    assert not [s for s in scripts(tmp_path)[1:] if "tvgw-probe" in s]
    # the TV's table itself is what it is without the probe
    plain = tmp_path / "plain"
    assert run_apply(plain, conf=conf.replace("TV_PROBE=on\n", "")).returncode == 0
    assert text.replace("\n".join(cmds) + "\n", "") == ruleset(plain)


@pytest.mark.parametrize(
    "address",
    [
        "10.10.10.1",
        "10.10.10.17",
        "10.10.10.15",
        "10.10.10.0",
        "10.10.10.255",
        "10.10.11.30",
        "198.51.100.7",
        "x",
    ],
)
def test_an_address_the_probe_may_not_have_turns_the_probe_off_and_never_the_apply(tmp_path, address):
    """The gateway's, the TV's, one of the DHCP pool, the network's, the broadcast, one outside TV_NET:
    the apply says so, loads the TV's table as it is without the probe, and finishes."""
    out = run_apply(tmp_path, conf=ON + f"TV_PROBE_IP={address}\n")
    assert out.returncode == 0, out.stderr
    assert "the probe is off for this apply" in out.stderr
    assert probe_commands(tmp_path) == [] and "tvgw: applied (uplink=direct" in out.stdout
    s = config.Settings(tv_probe="on", tv_probe_ip=address)
    with pytest.raises(ValueError, match="TV_PROBE_IP"):
        config.probe_side(s) if address != "x" else config.load("/nonexistent", tv_probe_ip="x")


def test_the_address_rules_are_the_same_in_the_shell_and_in_python(tmp_path):
    for n, last in enumerate((2, 9, 21, 30, 254)):
        address = f"10.10.10.{last}"
        assert config.probe_side(config.Settings(tv_probe="on", tv_probe_ip=address)) == address
        out = run_apply(tmp_path / str(n), conf=ON + f"TV_PROBE_IP={address}\n")
        assert out.returncode == 0 and f"ip saddr != {address} drop" in ruleset(tmp_path / str(n))


def test_probe_rules_nft_refuses_cost_the_tv_nothing(tmp_path):
    """nft refuses the transaction that carries the probe's rules (a kernel without something they need):
    nothing was changed by it, the TV's table is loaded as before the probe existed, and the apply goes
    on to switch forwarding on."""
    keep = 'cat >"$STUB_DIR/nft-script.$n" ;;'
    refuses = STUBS["nft"].replace(
        keep, 'cat >"$STUB_DIR/nft-script.$n"; ! grep -q probe_fwd "$STUB_DIR/nft-script.$n" || exit 1 ;;'
    )
    out = run_apply(tmp_path, conf=ON, stubs={"nft": refuses})
    assert out.returncode == 0, out.stderr
    assert "nft refused the probe's rules; the probe is off for this apply" in out.stderr
    loaded = scripts(tmp_path)
    assert "probe_fwd" in loaded[0] and "probe_fwd" not in loaded[1]
    plain = tmp_path / "plain"
    assert run_apply(plain, conf=CONF).returncode == 0
    assert loaded[1] == ruleset(plain)
    assert (tmp_path / "proc/sys/net/ipv4/conf/eth0/forwarding").read_text(encoding="utf-8") == "1\n"


def test_a_tv_chain_the_twin_cannot_follow_loads_no_probe_rules_at_all(tmp_path, monkeypatch):
    """The twin starts after the accept of everything not on the TV's port. Were that line reworded, a
    probe chain could end without its drop and hand packets back to a chain that accepts them: so a twin
    that is not whole is not loaded, and the probe says it has no rules."""
    reworded = APPLY.replace(
        '\t\tiifname != "$TV_IF" accept\n\t\t# (guard)',
        '\t\tmeta iifname != "$TV_IF" accept\n\t\t# (guard)',
        1,
    )
    assert reworded != APPLY
    monkeypatch.setattr(test_apply, "APPLY", reworded)
    out = run_apply(tmp_path, conf=ON)
    assert out.returncode == 0, out.stderr
    assert "the probe's rules could not be made from the TV's" in out.stderr
    assert probe_commands(tmp_path) == []


def test_a_ruleset_that_cannot_be_rendered_stops_the_apply_before_anything_is_loaded(tmp_path, monkeypatch):
    """The table's text is rendered first and loaded second. An error while it is made (here a variable
    nobody set) once handed nft an empty input through a process substitution: nft loaded nothing,
    said nothing, and the script went on to switch forwarding on with no filter. It stops, as the
    here-document before the probe stopped, and so does a rendering that is not whole."""
    broken = APPLY.replace(
        "\t\t$LEAK_DNS\n\t}\n}\n$ELEMENTS\n", "\t\t$LEAK_DNS\n\t}\n}\n$ELEMENTS\n$NOBODY_SET_THIS\n", 1
    )
    assert broken != APPLY
    for text, said in (
        (broken, "could not be rendered"),
        (APPLY.replace("chain post_leaks {", "chain leaks {", 1), "is not whole"),
    ):
        monkeypatch.setattr(test_apply, "APPLY", text)
        where = tmp_path / said.split()[0]
        out = run_apply(where)
        assert out.returncode == 1 and f"ruleset {said}" in out.stderr, out.stderr
        assert scripts(where) == []
        assert (where / "proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8") == "0\n"
        assert (where / "proc/sys/net/ipv4/conf/eth0/forwarding").read_text(encoding="utf-8") == "0\n"
    monkeypatch.setattr(
        test_apply, "APPLY", BEFORE.replace("\t\t$LEAK_DNS\n", "\t\t$LEAK_DNS\n\t\t$NOBODY_SET_THIS\n", 1)
    )
    assert run_apply(tmp_path / "old").returncode != 0  # as the script before the probe did


@pytest.mark.parametrize(
    ("old", "new", "said"),
    [
        # a rule of the TV's put before "not the TV's port", where the twin does not begin
        (
            '\t\tiifname != "$TV_IF" accept\n\t\t# (guard)',
            '\t\tiifname "$TV_IF" tcp dport 9 counter drop\n\t\tiifname != "$TV_IF" accept\n\t\t# (guard)',
            "a rule stands before",
        ),
        # a rule that names the TV's port as the way out
        (
            "\t\t$QUIC\n",
            '\t\t$QUIC\n\t\toifname "$TV_IF" counter drop\n',
            "names the TV's port as the way out",
        ),
        # verdicts the copy does not know
        ("\t\t$QUIC\n", "\t\t$QUIC\n\t\tudp dport 5353 counter return\n", "does not copy (return)"),
        ("\t\t$QUIC\n", "\t\t$QUIC\n\t\ttcp dport 25 queue\n", "does not copy (queue)"),
        ("\t\t$QUIC\n", "\t\t$QUIC\n\t\ttcp dport 80 redirect to :8080\n", "does not copy (redirect)"),
        ("\t\t$QUIC\n", "\t\t$QUIC\n\t\ttcp dport 25 jump elsewhere\n", "a jump to a chain that has no twin"),
        ("\t\t$QUIC\n", "\t\t$QUIC\n\t\ttcp dport 25 synproxy mss 1460\n", "does not copy (synproxy)"),
        ("\t\t$QUIC\n", "\t\t$QUIC\n\t\ttcp dport 25 ct helper set ftp\n", None),  # a `set` is copied
    ],
    ids=["before-the-marker", "oifname", "return", "queue", "redirect", "jump-elsewhere", "synproxy", "set"],
)
def test_a_rule_the_twin_cannot_copy_faithfully_turns_the_probe_off_and_names_the_rule(
    tmp_path, monkeypatch, old, new, said
):
    """Shapes the TV's chains do not have today and may have tomorrow. Never a twin that silently
    differs from the TV's rules: the derivation stops, one line names the rule, no probe rule is loaded
    for that apply (so the probe says it has none, which the check shows as a warning), and the TV's own
    table loads with the new rule in it."""
    assert APPLY.count(old) == 1, old
    monkeypatch.setattr(test_apply, "APPLY", APPLY.replace(old, new))
    out = run_apply(tmp_path, conf=ON)
    assert out.returncode == 0, out.stderr
    added = (
        new.replace(old.replace("\t\t# (guard)", ""), "")
        .strip()
        .split("\n")[0]
        .strip()
        .replace("$TV_IF", "eth0")
    )
    if said is None:
        assert f"add rule inet tvgw probe_out {added}" in probe_commands(tmp_path)
        return
    assert "tvgw: the probe's rules: " in out.stderr and said in out.stderr and added in out.stderr
    assert "the probe is off for this apply" in out.stderr and probe_commands(tmp_path) == []
    assert added in ruleset(tmp_path) and "tvgw: applied (uplink=direct" in out.stdout


def test_two_tv_port_rules_of_a_chain_keep_their_order_at_the_head_of_it(tmp_path):
    """pre_nat has two: the redirect of UDP and of TCP lookups. Each is written to the head of the
    chain, so the last is written first."""
    assert run_apply(tmp_path, conf=ON).returncode == 0
    mine = [c for c in probe_commands(tmp_path) if c.startswith("insert rule inet tvgw pre_nat ")]
    assert [("udp" in c, "tcp" in c) for c in mine] == [(False, True), (True, False)]
    tv = [ln for ln in chain(ruleset(tmp_path), "pre_nat") if 'iifname "eth0"' in ln]
    assert ["udp dport 53" in ln for ln in tv] == [True, False]  # the TV's order: udp, then tcp


def test_the_tvs_pin_is_left_out_by_what_it_is_not_by_its_words(tmp_path, monkeypatch):
    """The pin is the rule the script itself made (PIN_RULE), matched whole; reworded, it is still left
    out, and a rule that merely carries the same comment is copied like any other."""
    reworded = APPLY.replace(
        'counter drop comment \\"TV source is not the TV\\""', 'counter drop comment \\"the pin\\""'
    )
    assert reworded != APPLY
    monkeypatch.setattr(test_apply, "APPLY", reworded)
    out = run_apply(tmp_path, conf=ON + f"TV_MAC={MAC}\nTV_IP=10.10.10.17\n")
    assert out.returncode == 0, out.stderr
    assert "the pin" in ruleset(tmp_path) and not [c for c in probe_commands(tmp_path) if "10.10.10.17" in c]
    assert [c for c in probe_commands(tmp_path) if c.startswith("add rule inet tvgw probe_fwd ")]


def test_the_check_renders_the_probes_rules_for_nft_to_judge(tmp_path):
    from test_apply_check import checked, run_check

    assert run_check(tmp_path, conf=ON).returncode == 0
    assert "add rule inet tvgw probe_out " in checked(tmp_path)[0]
    refused = run_check(tmp_path / "refused", conf=ON, refuse="probe_fwd")
    assert refused.returncode == 1  # a deploy must hear that the probe's rules do not load


# ---- the confirmation ----------------------------------------------------------------------------------

GOOD_FILES = [
    "inet-tvgw.nft", "inet-tvgw.nft.was", "inet-tvgw_capture.nft", "inet-tvgw_gate.nft", "inet-tvgw_gate.nft.was",
    "netdev-tvgw_l2.nft", "rule60", "sysctl", "table100",
]  # fmt: skip


def tvgw_calls(tmp_path) -> list[str]:
    path = tmp_path / "stub" / "tvgw.calls"
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def test_report_with_a_probe_that_passes_keeps_last_good_arms_the_timer_and_cancels_it(tmp_path):
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=report\n", revert=False)
    assert out.returncode == 0, out.stderr
    assert "tvgw: confirm: pass (before the apply: pass)" in out.stdout
    good = tmp_path / "run" / "tvgw" / "last-good"
    assert sorted(p.name for p in good.iterdir()) == GOOD_FILES
    assert (good / "inet-tvgw.nft").read_text(encoding="utf-8") == (
        "table inet tvgw\ndelete table inet tvgw\ntable inet tvgw {\n}\n"
    )
    # a table that was not there is one to take away again, and says so by having no `.was`
    assert (good / "netdev-tvgw_l2.nft").read_text(
        encoding="utf-8"
    ) == "table netdev tvgw_l2\ndelete table netdev tvgw_l2\n"
    # the switches as they stood before this apply wrote them, by their files
    saved = dict(ln.split(" ", 1) for ln in (good / "sysctl").read_text(encoding="utf-8").splitlines())
    assert saved[f"{tmp_path}/proc/sys/net/ipv4/ip_forward"] == "0"
    assert saved[f"{tmp_path}/proc/sys/net/ipv4/conf/eth0/forwarding"] == "1"
    # armed before the first change, with the restore it would run, and cancelled once the probe passed
    (armed,) = (tmp_path / "stub" / "setsid.calls").read_text(encoding="utf-8").splitlines()
    assert (
        "--restore" in armed and f" 75 {tmp_path}/tvgw-apply {good} " in armed and armed.endswith(" report")
    )
    assert not (good / "armed").exists()
    assert spool(tmp_path) == [
        ["apply", spool(tmp_path)[0][1], "changed"],
        ["confirm", "report", "pass", "-"],
    ]
    assert list((tmp_path / "run" / "tvgw").glob("confirm.*")) == []
    assert len(tvgw_calls(tmp_path)) == 1  # the probe ran once, around the apply, and was not asked again


@pytest.mark.parametrize(
    ("last", "age", "ip"),
    [
        (None, 0, None),  # no probe has ever run
        ("fail", 60, None),  # the last one did not pass
        ("unknown", 60, None),
        ("pass", 1200, None),  # it passed, twenty minutes ago
        ("pass", 60, "rule-without-route"),  # rule 60 stands and table 100 has no default route: the flap
    ],
)
def test_an_apply_never_waits_for_the_probe_when_the_path_is_not_known_whole(tmp_path, last, age, ip):
    """The uplink came back and the apply's job is to put the route back: every second it spent probing
    a broken path would be a second more of outage. Without a pass in the last 15 minutes, or with the
    kernel's own state showing the TV's route broken, the probe is not started at all, nothing is kept
    or armed, and the apply does what it does without the setting."""
    more = None
    if ip:
        answer = "\"rule show priority 60\") printf '60:\\tfrom 10.10.10.0/24 lookup 100 \\n' ;;"
        more = {"ip": STUBS["ip"].replace("exit 0\n", 'case "$*" in\n' + answer + "\nesac\nexit 0\n")}
    started = time.monotonic()
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=report\n", last=last, age=age, more=more, revert=False)
    assert out.returncode == 0, out.stderr
    assert "this apply starts at once and is not confirmed" in out.stderr
    assert tvgw_calls(tmp_path) == [] and time.monotonic() - started < 20
    assert not (tmp_path / "run" / "tvgw" / "last-good").exists()
    assert not (tmp_path / "stub" / "setsid.calls").exists()
    assert "tvgw: applied (uplink=direct" in out.stdout and [row[0] for row in spool(tmp_path)] == ["apply"]


def test_an_apply_waits_eight_seconds_for_the_verdict_before_and_no_longer(tmp_path):
    silent = TVGW.replace('[ -n "$PRE" ] || exit 4', "sleep 60")
    started = time.monotonic()
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=report\n", more={"tvgw": silent}, revert=False)
    assert out.returncode == 0, out.stderr
    assert 7 < time.monotonic() - started < 40
    assert "tvgw: confirm: unknown (before the apply: unknown)" in out.stdout
    assert not (tmp_path / "stub" / "setsid.calls").exists()
    assert 'confirm_wait "$CONFIRM_DIR/pre" 80' in APPLY  # tenths of a second


def test_where_systemd_runs_the_timer_is_systemds_own_and_is_stopped_on_a_pass(tmp_path):
    """On a gateway the restore is a transient systemd timer, which outlives the script and the unit
    that ran it: the unit's name, the 75 seconds, and the restore with this apply's token. A pass stops
    the timer. No detached process is started beside it."""
    (tmp_path / "run" / "systemd" / "system").mkdir(parents=True)
    record = '#!/bin/sh\nprintf \'%s\\n\' "$*" >>"$STUB_DIR/{name}.calls"\n'
    more = {name: record.format(name=name) for name in ("systemd-run", "systemctl")}
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=revert\n", more=more)
    assert out.returncode == 0, out.stderr
    good = tmp_path / "run" / "tvgw" / "last-good"
    (armed,) = (tmp_path / "stub" / "systemd-run.calls").read_text(encoding="utf-8").splitlines()
    head = "--quiet --collect --unit=tvgw-apply-restore --on-active=75 --timer-property=AccuracySec=1s /bin/bash "
    assert armed.startswith(f"{head}{tmp_path}/tvgw-apply --restore {good} ") and armed.endswith(" revert")
    assert not (tmp_path / "stub" / "setsid.calls").exists()
    asked = (tmp_path / "stub" / "systemctl.calls").read_text(encoding="utf-8").splitlines()
    assert asked[-1] == "stop tvgw-apply-restore.timer" and not (good / "armed").exists()


def test_report_says_what_it_would_have_undone_and_undoes_nothing(tmp_path):
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=report\n", post="fail path", revert=False)
    assert out.returncode == 0, out.stderr
    assert (
        "passed before this apply and fails after it (path); APPLY_CONFIRM=report: nothing was changed"
        in out.stderr
    )
    assert spool(tmp_path)[-1] == ["confirm", "report", "would_revert", "path"]
    assert not [c for c in nft_calls(tmp_path) if "last-good" in c and c.startswith("-f")]
    assert "tvgw: applied (uplink=direct" in out.stdout
    assert not (tmp_path / "run" / "tvgw" / "last-good" / "armed").exists()


def test_on_a_live_gateway_revert_says_it_is_not_supported_yet_and_acts_as_report(tmp_path):
    """The script as it ships. What a revert still lacks is written in design decision 65; until it has
    it, the setting confirms and reports, and undoes nothing."""
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=revert\n", post="fail path", revert=False)
    assert out.returncode == 0, out.stderr
    assert "APPLY_CONFIRM=revert is not supported on a live gateway yet" in out.stderr
    assert "APPLY_CONFIRM=report: nothing was changed" in out.stderr
    assert spool(tmp_path)[-1] == ["confirm", "report", "would_revert", "path"]
    assert not [c for c in nft_calls(tmp_path) if "last-good" in c and c.startswith("-f")]
    (armed,) = (tmp_path / "stub" / "setsid.calls").read_text(encoding="utf-8").splitlines()
    assert armed.endswith(" report")  # the timer too would only say
    assert APPLY.count("\nREVERT_SUPPORTED=no\n") == 1 and "REVERT_SUPPORTED=yes" not in APPLY


def test_revert_puts_last_good_back_once_probes_again_and_says_both(tmp_path):
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=revert\n", post="fail dot")
    assert out.returncode == 3
    assert "fails after it (dot); last-good was put back, and the probe now says: pass" in out.stderr
    assert "This apply is undone; nothing more is tried" in out.stderr
    good = tmp_path / "run" / "tvgw" / "last-good"
    restores = [c for c in nft_calls(tmp_path) if c.startswith("-f ") and "last-good" in c]
    # the filter first; then the tables that were not there are taken away; the gate's, which stood
    # before and stands now, is left as it is, with the addresses its feeder collected
    assert restores == [f"-f {good}/{n}.nft" for n in ("inet-tvgw", "netdev-tvgw_l2", "inet-tvgw_capture")]
    assert spool(tmp_path)[-1] == ["confirm", "revert", "reverted_pass", "dot"]
    # a switch goes back to what was saved: ip_forward was off before this apply
    assert (tmp_path / "proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8") == "0\n"
    assert [c.split()[:2] for c in tvgw_calls(tmp_path)] == [
        ["probe", "--across"],
        ["probe"],
    ]  # one look after
    # rule 60 and table 100 were as last-good had them, so the restore wrote neither
    ip = (tmp_path / "stub" / "ip.calls").read_text(encoding="utf-8").splitlines()
    assert not [c for c in ip if " pref 60" in c or c.startswith(("route del", "route replace 10.10.10.30"))]


def test_a_restore_that_does_not_help_is_said_and_not_tried_again(tmp_path):
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=revert\n", post="fail path", again=3)
    assert out.returncode == 3 and "the probe now says: fail" in out.stderr
    assert spool(tmp_path)[-1] == ["confirm", "revert", "reverted_fail", "path"]
    assert (
        len([c for c in nft_calls(tmp_path) if c == f"-f {tmp_path}/run/tvgw/last-good/inet-tvgw.nft"]) == 1
    )


@pytest.mark.parametrize(
    ("pre", "post", "said", "outcome"),
    [
        ("pass -", "unknown path", "confirm: unknown (before the apply: pass)", "unknown"),
        ("unknown probe", "fail path", "did not pass before this apply either (unknown)", "failing_before"),
        ("fail path", "fail path", "did not pass before this apply either (fail)", "failing_before"),
        ("fail path", "pass -", "confirm: pass (before the apply: fail)", "pass"),
        (
            "pass -",
            "",
            "confirm: unknown (before the apply: pass)",
            "unknown",
        ),  # the probe died after the apply
        ("", "fail path", "confirm: unknown (before the apply: unknown)", "unknown"),  # it never spoke
    ],
)
def test_revert_never_undoes_on_an_unknown_or_on_a_fault_that_was_there_before(
    tmp_path, pre, post, said, outcome
):
    """An unknown never reverts: the uplink down, a probe that crashed, hung or is missing. And a probe
    that did not pass before the apply gives nothing to go back to, whatever it says after."""
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=revert\n", pre=pre, post=post)
    assert out.returncode == 0, out.stderr
    assert said in out.stdout + out.stderr
    assert spool(tmp_path)[-1][:3] == ["confirm", "revert", outcome]
    assert not [c for c in nft_calls(tmp_path) if "last-good" in c and c.startswith("-f")]
    assert "tvgw: applied (uplink=direct" in out.stdout
    assert not (tmp_path / "run" / "tvgw" / "last-good" / "armed").exists()
    if pre != "pass -":  # nothing is kept, and no timer armed, for a state the probe did not see working
        assert not (tmp_path / "stub" / "setsid.calls").exists()


@pytest.mark.parametrize(
    "broken",
    [
        {
            "ip": STUBS["ip"].replace(
                "exit 0\n", 'case "$*" in "rule show priority 60") exit 2 ;; esac\nexit 0\n'
            )
        },
        {
            "ip": STUBS["ip"].replace(
                "exit 0\n",
                'case "$*" in "route show table 100") echo "RTNETLINK answers: busy" >&2; exit 2 ;; esac\nexit 0\n',
            )
        },
        {"nft": CONFIRM_NFT.replace('"list tables") ', '"list tables") exit 1; ')},
    ],
    ids=["rule-listing-fails", "route-listing-fails", "tables-listing-fails"],
)
def test_a_listing_that_failed_is_no_last_good(tmp_path, broken):
    """A listing that failed, kept as an empty file, would read at a restore as "there was no rule 60" or
    "the table was not there", and the restore would take away what it could not list. Nothing is kept
    and nothing armed; the apply goes on."""
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=revert\n", post="fail path", more=broken)
    assert out.returncode == 0, out.stderr
    assert "the live state could not be kept as last-good; nothing can be undone" in out.stderr
    assert not (tmp_path / "run" / "tvgw" / "last-good").exists()
    assert not (tmp_path / "stub" / "setsid.calls").exists()
    assert spool(tmp_path)[-1][:3] == ["confirm", "revert", "failing_before"]
    assert not [c for c in nft_calls(tmp_path) if "last-good" in c and c.startswith("-f")]


def test_a_table_100_that_does_not_exist_is_an_empty_one_not_a_failed_listing(tmp_path):
    none = {
        "ip": STUBS["ip"].replace(
            "exit 0\n",
            'case "$*" in "route show table 100") echo "Error: ipv4: FIB table does not exist." >&2; exit 2 ;; esac\nexit 0\n',
        )
    }
    out = run_confirm(tmp_path, ON + "APPLY_CONFIRM=report\n", more=none, revert=False)
    assert out.returncode == 0 and "tvgw: confirm: pass (before the apply: pass)" in out.stdout
    assert (tmp_path / "run" / "tvgw" / "last-good" / "table100").read_text(encoding="utf-8") == ""


def test_confirm_without_the_probe_or_without_tvgw_only_says_so(tmp_path):
    out = run_apply(tmp_path / "a", conf=CONF + "APPLY_CONFIRM=revert\n")
    assert out.returncode == 0 and "needs TV_PROBE=on; this apply is not confirmed" in out.stderr
    out = run_apply(tmp_path / "b", conf=ON + "APPLY_CONFIRM=revert\n")  # /usr/local/bin/tvgw is not here
    assert out.returncode == 0 and "is not there; this apply is not confirmed" in out.stderr
    for side in ("a", "b"):
        assert [row[0] for row in spool(tmp_path / side)] == ["apply"]


def test_the_check_confirms_nothing(tmp_path):
    from test_apply_check import nft_calls as check_calls
    from test_apply_check import run_check

    out = run_check(tmp_path, conf=ON + "APPLY_CONFIRM=revert\n")
    assert out.returncode == 0, out.stderr
    assert set(check_calls(tmp_path)) == {"-c -f -"} and not (tmp_path / "run" / "tvgw").exists()


# ---- the restore the timer runs -------------------------------------------------------------------------


def restore(
    tmp_path, token: str, mode: str, ip: str | None = None, flock: str | None = None
) -> subprocess.CompletedProcess:
    """`tvgw-apply --restore` over the last-good a confirmed apply left in tmp_path."""
    import os

    for name, body in {"ip": ip or STUBS["ip"], "flock": flock or STUBS["flock"]}.items():
        (tmp_path / "bin" / name).write_text(body, encoding="utf-8")
    env = {
        "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
        "STUB_DIR": str(tmp_path / "stub"),
        "FAKE_PROC": str(tmp_path / "proc"),
    }
    argv = [
        "bash",
        str(tmp_path / "tvgw-apply"),
        "--restore",
        str(tmp_path / "run/tvgw/last-good"),
        token,
        mode,
    ]
    return subprocess.run(argv, env=env, capture_output=True, text=True, encoding="utf-8")


def armed_apply(tmp_path) -> Path:
    """A confirmed apply, then its last-good armed again as if that apply had died before it cancelled."""
    assert run_confirm(tmp_path, ON + "APPLY_CONFIRM=revert\n").returncode == 0
    good = tmp_path / "run" / "tvgw" / "last-good"
    (good / "armed").write_text("token-1\n", encoding="utf-8")
    (tmp_path / "stub" / "nft.calls").write_text("", encoding="utf-8")
    (tmp_path / "stub" / "ip.calls").write_text("", encoding="utf-8")
    return good


def test_the_timers_restore_puts_everything_back_and_only_what_differs(tmp_path):
    """The saved state, with the kernel now holding what an apply killed halfway left: forwarding on,
    rule 60 gone, a route in table 100 that last-good did not have, one it had missing. The filter is
    loaded first; a switch, the rule and a route are written only where they differ; and a missing route
    is written before a stray one is removed, so table 100 is never without its default route."""
    good = armed_apply(tmp_path)
    (good / "rule60").write_text("from 10.10.10.0/24 lookup 100\n", encoding="utf-8")
    (good / "table100").write_text(
        "default via 203.0.113.1 dev wlan0\n10.10.10.0/24 dev eth0 scope link src 10.10.10.1\n",
        encoding="utf-8",
    )
    now = STUBS["ip"].replace(
        "exit 0\n",
        'case "$*" in\n"route show table 100") echo "10.10.10.0/24 dev eth0 scope link src 10.10.10.1 linkdown ";'
        ' echo "192.0.2.0/24 dev wlan0 scope link"; echo "10.10.10.30 dev tvgw-probe scope link src 10.10.10.1" ;;\n'
        "esac\nexit 0\n",
    )
    out = restore(tmp_path, "token-1", "revert", ip=now)
    assert out.returncode == 0, out.stderr
    assert "the apply did not finish; last-good was put back" in out.stderr
    loads = [c for c in nft_calls(tmp_path) if c.startswith("-f ")]
    assert loads == [f"-f {good}/{n}.nft" for n in ("inet-tvgw", "netdev-tvgw_l2", "inet-tvgw_capture")]
    assert (tmp_path / "proc/sys/net/ipv4/ip_forward").read_text(encoding="utf-8") == "0\n"
    writes = [
        c
        for c in (tmp_path / "stub" / "ip.calls").read_text(encoding="utf-8").splitlines()
        if "show" not in c
    ]
    assert (
        writes
        == [
            "rule del pref 60",
            "rule add pref 60 from 10.10.10.0/24 lookup 100",
            "route replace default via 203.0.113.1 dev wlan0 table 100",  # first what is missing
            "route del 192.0.2.0/24 dev wlan0 scope link table 100",  # then what should not be there; not the probe's
        ]
    )
    assert spool(tmp_path)[-1] == ["confirm", "revert", "timer_restored", "timer"]
    assert not (good / "armed").exists()
    assert "last-good was put back" in (good / "restore.log").read_text(encoding="utf-8")
    # the counters either side of the reload, for verify to store the reset
    run = tmp_path / "run" / "tvgw"
    assert (run / "counters.before-apply").exists() and (run / "counters.after-apply").exists()


def test_the_gates_table_is_never_emptied_by_a_restore(tmp_path):
    """Deleted and made again, the gate's set would lose every address its feeder added since the save.
    Where the table stood before and stands now it is left alone; where the apply made it, it is taken
    away; where the apply took it away, it is put back."""
    good = armed_apply(tmp_path)
    assert restore(tmp_path, "token-1", "revert").returncode == 0
    assert not [c for c in nft_calls(tmp_path) if "tvgw_gate" in c and c.startswith("-f")]
    (good / "armed").write_text("token-2\n", encoding="utf-8")
    (good / "inet-tvgw_gate.nft.was").unlink()  # it was not there when last-good was kept
    (tmp_path / "stub" / "nft.calls").write_text("", encoding="utf-8")
    assert restore(tmp_path, "token-2", "revert").returncode == 0
    assert f"-f {good}/inet-tvgw_gate.nft" in nft_calls(tmp_path)


def test_a_restore_never_runs_without_the_lock(tmp_path):
    """An apply that holds the lock is alive, and may be a later one in the middle of its own changes."""
    good = armed_apply(tmp_path)
    out = restore(tmp_path, "token-1", "revert", flock="#!/bin/sh\nexit 1\n")
    assert out.returncode == 0 and "an apply holds the lock; nothing was restored" in out.stderr
    assert nft_calls(tmp_path) == [] and (good / "armed").exists()


def test_every_apply_defuses_a_timer_an_earlier_apply_left_armed(tmp_path):
    """Also an apply that confirms nothing: a restore armed for an apply that died must never go over
    the work of the one that came after it."""
    good = armed_apply(tmp_path)
    old, test_apply.APPLY = test_apply.APPLY, APPLY.replace("/usr/local/bin/tvgw", f"{tmp_path}/bin/tvgw")
    try:
        out = run_apply(tmp_path, conf=CONF, stubs={**EXTRA, "nft": CONFIRM_NFT})
    finally:
        test_apply.APPLY = old
    assert out.returncode == 0 and not (good / "armed").exists()
    assert (
        restore(tmp_path, "token-1", "revert").stderr == ""
    )  # and the old timer, firing, finds nothing to do


def test_with_the_probe_off_an_apply_removes_what_a_killed_probe_left(tmp_path):
    (tmp_path / "run" / "netns").mkdir(parents=True)
    (tmp_path / "run" / "netns" / "tvgw-probe").write_text("", encoding="utf-8")
    assert run_apply(tmp_path, conf=CONF).returncode == 0
    calls = (tmp_path / "stub" / "ip.calls").read_text(encoding="utf-8").splitlines()
    assert "netns del tvgw-probe" in calls
    kept = tmp_path / "on"
    (kept / "run" / "netns").mkdir(parents=True)
    (kept / "run" / "netns" / "tvgw-probe").write_text("", encoding="utf-8")
    assert run_apply(kept, conf=ON).returncode == 0  # with the probe on, the next probe run removes it
    assert "netns del tvgw-probe" not in (kept / "stub" / "ip.calls").read_text(encoding="utf-8").splitlines()


def test_a_cancelled_or_superseded_timer_does_nothing(tmp_path):
    good = armed_apply(tmp_path)
    out = restore(tmp_path, "an-older-token", "revert")
    assert out.returncode == 0 and out.stderr == ""
    (good / "armed").unlink()
    out = restore(tmp_path, "token-1", "revert")
    assert out.returncode == 0 and out.stderr == ""
    assert nft_calls(tmp_path) == [] and spool(tmp_path)[-1][2] == "pass"


def test_in_report_mode_the_timer_only_says_what_it_would_have_done(tmp_path):
    armed_apply(tmp_path)
    out = restore(tmp_path, "token-1", "report")
    assert out.returncode == 0 and "APPLY_CONFIRM=report: nothing was changed" in out.stderr
    assert nft_calls(tmp_path) == []
    assert spool(tmp_path)[-1] == ["confirm", "report", "timer_would_restore", "timer"]


def test_the_restore_reads_no_settings_and_compares_before_it_writes_a_route():
    """The timer may fire while the settings file is the very thing that broke the apply, so the restore
    runs before the file is sourced. And it follows the 2026-10-30 lesson on its own account: the rule
    and each route are compared with the saved ones and written only on a difference, a missing route
    before a stray one is removed."""
    head = APPLY[: APPLY.index("\n. /etc/tvgw/tvgw.conf\n")]
    assert 'if [ "${1:-}" = --restore ]; then' in head and "restore_state() {" in head
    body = head[head.index("restore_state() {") :]
    assert body.index('if [ "$(rule60)" != "$want" ]; then') < body.index("ip rule del pref 60")
    assert body.index('grep -qxF -- "$line" <<<"$now" ||') < body.index("ip route replace $line table 100")
    assert body.index("ip route replace $line table 100") < body.index("ip route del $line table 100")
    assert "forwarding=0" not in body and "delete table inet tvgw\n" not in body.replace(
        "delete table %s", ""
    )
    # the tables it saves are the ones the apply loads that can refuse or steer traffic; the NTP count (which
    # refuses nothing and keeps its counts across applies) and the guard (its own unit's) are listed, not saved
    assert 'MANAGED_TABLES=("inet tvgw" "netdev tvgw_l2" "inet tvgw_gate" "inet tvgw_capture")' in head
    assert (
        'for t in "inet tvgw" "netdev tvgw_l2" "inet tvgw_gate" "inet tvgw_ntp" "inet tvgw_capture" "inet tvgw_guard"; do'
        in APPLY
    )
    assert "policy accept" in APPLY[APPLY.index("add table inet tvgw_ntp") : APPLY.index("# ---- (ntp) end")]


# ---- the ledger reads what the apply wrote ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "kind", "cls"),
    [
        ("confirm\treport\tpass\t-", "apply_confirm", "B"),
        ("confirm\treport\twould_revert\tallowed", "apply_would_revert", "A"),
        ("confirm\trevert\tfailing_before\tdot", "apply_confirm", "B"),
        ("confirm\trevert\treverted_pass\tallowed", "apply_restored", "A"),
        ("confirm\trevert\ttimer_restored\ttimer", "apply_restored", "A"),
        ("confirm\treport\ttimer_would_restore\ttimer", "apply_would_revert", "A"),
    ],
)
def test_a_confirmation_is_one_row_of_the_change_ledger(line, kind, cls):
    row = ledger._spool_row(["1793026800", *line.split("\t")], config.Settings(), None)
    assert row is not None and row.kind == kind and row.source == "confirm"
    assert ledger.KINDS[kind][0] == cls
    mode, outcome, stage = line.split("\t")[1:]
    assert row.subject == outcome and row.detail == {"mode": mode, "outcome": outcome, "stage": stage}
    assert kind in ledger.GROUPS["Gateway"]
    assert ledger._spool_row(["1793026800", "confirm", "off", "pass"], config.Settings(), None) is None


def test_every_stage_word_fits_the_spools_field():
    """The spool takes plain words; a stage the ledger could not read would be stored as `?`."""
    for name in probe.STAGE_PLAIN:
        assert ledger._clean_field(name) == name
