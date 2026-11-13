"""(fail closed) An apply that ends with no filter loaded leaves the TV dark, never unfiltered (design
decision 5), against the stubs of test_apply.py.

Forwarding is switched on last, which kept the promise only where forwarding was off before the apply.
With `net.ipv4.ip_forward=1` left on by another program, a first apply that stopped early left the TV
forwarded with no `inet tvgw` at all (pass 6, L4-3). And a kernel started without IPv6 stopped every
apply before its load (L4-4). Each test here states one line of the new promise."""

import re
import shutil

import pytest
import test_apply
from test_apply import APPLY, CONF, PROC, STUBS, nft_changes, run_apply

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")

FORWARDING = "net/ipv4/conf/eth0/forwarding"
V6_SWITCH = "net/ipv6/conf/eth0/disable_ipv6"
DARK = "tvgw: no filter is loaded, so forwarding from the TV's port {} is off"
# an apply that stops before its own load: its settings, and whether nft refuses the ruleset
FAILURES = {
    "a switch that is nearly right": (CONF + "BLOCK_QUIC=Yes\n", False),
    "a TV side that covers too much": (CONF + "TV_NET=0.0.0.0/0\n", False),
    "settings that do not parse": (CONF + "if\n", False),
    "a ruleset nft refuses": (CONF, True),
}


def nft(*, loaded: bool = False, refuses: bool = False) -> str:
    """test_apply's nft, on a gateway where an earlier apply's filter is `loaded` or not, and which
    `refuses` every ruleset or takes it."""
    cases = ('"list tables") echo "table inet tvgw" ;;\n' if loaded else "") + (
        '"-f -") cat >/dev/null; exit 1 ;;\n' if refuses else ""
    )
    return STUBS["nft"].replace('case "$*" in\n', 'case "$*" in\n' + cases, 1)


def switch(tmp_path, key: str) -> str:
    return (tmp_path / "proc" / "sys" / key).read_text(encoding="utf-8").strip()


@pytest.mark.parametrize("loaded", [False, True], ids=["no filter", "an earlier filter"])
@pytest.mark.parametrize("inherited", ["0", "1"], ids=["forwarding off", "forwarding left on"])
@pytest.mark.parametrize("failure", FAILURES)
def test_an_apply_that_fails_leaves_the_tv_dark_unless_an_earlier_filter_holds(
    tmp_path, failure, inherited, loaded
):
    """With no filter, forwarding on the TV's port goes off, and the apply says so when it switched it.
    With an earlier apply's filter still loaded the old rules hold and nothing is touched. Either way the
    apply has failed, whatever status the shell had: after settings that do not parse, an EXIT trap can
    read `$?` as 0."""
    conf, refuses = FAILURES[failure]
    out = run_apply(
        tmp_path,
        conf=conf,
        stubs={"nft": nft(loaded=loaded, refuses=refuses)},
        preset={FORWARDING: inherited},
    )
    assert out.returncode != 0
    assert switch(tmp_path, FORWARDING) == (inherited if loaded else "0")
    assert (DARK.format("eth0") in out.stderr) == (inherited == "1" and not loaded)


def test_an_apply_that_loads_its_filter_never_looks_for_it_and_forwards(tmp_path):
    """The look is for an apply that ends before its own load. One that loaded its filter knows, makes no
    call more than before, and switches forwarding on last, as ever."""
    out = run_apply(tmp_path, preset={FORWARDING: "1"})
    assert out.returncode == 0, out.stderr
    assert "list tables" not in (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()
    assert switch(tmp_path, FORWARDING) == "1" and "no filter is loaded" not in out.stderr


def test_the_port_the_last_apply_filtered_goes_dark_with_the_settings_port(tmp_path):
    """The settings name the new port after a TV_IF edit while the TV is still on the old one: both are
    switched off, each with its line, and a port that is already off gets none."""
    moved_proc = (*PROC, "net/ipv4/conf/eth1/forwarding", "net/ipv4/conf/eth2/forwarding")
    (tmp_path / "run" / "tvgw").mkdir(parents=True)
    (tmp_path / "run" / "tvgw" / "settings.applied").write_text("TV_IF=eth1\n", encoding="utf-8")
    out = run_apply(
        tmp_path,
        conf=CONF + "TV_IF=eth0\nBLOCK_QUIC=Yes\n",
        proc=moved_proc,
        preset={FORWARDING: "1", "net/ipv4/conf/eth1/forwarding": "1", "net/ipv4/conf/eth2/forwarding": "1"},
    )
    assert out.returncode != 0
    assert [switch(tmp_path, f"net/ipv4/conf/{dev}/forwarding") for dev in ("eth0", "eth1", "eth2")] == [
        "0",
        "0",
        "1",  # no port of the TV's: not this script's to switch
    ]
    assert [line for line in out.stderr.splitlines() if "no filter is loaded" in line] == [
        DARK.format("eth0"),
        DARK.format("eth1"),
    ]


LOGGED_FLOCK = '#!/bin/sh\nprintf \'%s\\n\' "$*" >>"$STUB_DIR/flock.calls"\nexit 0\n'
# another apply's first load goes in while this one waits for the lock: the filter is listed only then
LOADED_BY_THEN = STUBS["nft"].replace(
    'case "$*" in\n',
    'case "$*" in\n"list tables") [ ! -e "$STUB_DIR/flock.calls" ] || echo "table inet tvgw" ;;\n',
    1,
)


@pytest.mark.parametrize(
    ("failure", "locks"),
    [
        ("a switch that is nearly right", ["-w 30 9"]),  # it ended before the lock: the look takes it
        ("a ruleset nft refuses", ["9"]),  # it ended under its own lock: the look takes none
    ],
)
def test_an_apply_that_ended_before_the_lock_takes_it_for_its_second_look(tmp_path, failure, locks):
    conf, refuses = FAILURES[failure]
    out = run_apply(tmp_path, conf=conf, stubs={"nft": nft(refuses=refuses), "flock": LOGGED_FLOCK})
    assert out.returncode != 0
    assert (tmp_path / "stub" / "flock.calls").read_text(encoding="utf-8").splitlines() == locks


def test_a_filter_another_apply_loads_meanwhile_keeps_the_tv_online(tmp_path):
    """The first look finds no filter because another apply's first load is on its way. The second look
    waits for that apply under the lock, finds its filter, and switches nothing off."""
    out = run_apply(
        tmp_path,
        conf=CONF + "BLOCK_QUIC=Yes\n",
        stubs={"nft": LOADED_BY_THEN, "flock": LOGGED_FLOCK},
        preset={FORWARDING: "1"},
    )
    assert out.returncode != 0
    assert switch(tmp_path, FORWARDING) == "1" and "no filter is loaded" not in out.stderr


def test_settings_that_stop_before_naming_the_port_still_darken_the_port_their_file_names(tmp_path):
    """`TV_NAME=Living room` runs `room` and ends the read before the TV_IF line, at a boot with nothing
    applied yet. The file's own line names the port: that one goes dark, and the default port, which may
    be the uplink here, is left alone."""
    eth1 = "net/ipv4/conf/eth1/forwarding"
    out = run_apply(
        tmp_path,
        conf="TV_NAME=Living room\nTV_IF='eth1'\n" + CONF,
        proc=(*PROC, eth1),
        preset={FORWARDING: "1", eth1: "1"},
    )
    assert out.returncode != 0
    assert (switch(tmp_path, FORWARDING), switch(tmp_path, eth1)) == ("1", "0")
    assert DARK.format("eth1") in out.stderr and DARK.format("eth0") not in out.stderr


def test_an_apply_that_dies_after_its_load_has_failed_whatever_the_shell_says(tmp_path, monkeypatch):
    """bash 3.2 hands an EXIT trap a `$?` of 0 after a fatal error such as an unset variable, so with a
    trap always set a crash would read as success. An apply that reaches none of its own ends has
    failed. Its filter is in, so nothing is switched off."""
    crash = "FILTER_LOADED=yes"
    monkeypatch.setattr(test_apply, "APPLY", APPLY.replace(crash, crash + '\n: "$NOT_SET_ANYWHERE"', 1))
    out = run_apply(tmp_path)
    assert out.returncode != 0 and "NOT_SET_ANYWHERE" in out.stderr
    assert "no filter is loaded" not in out.stderr


def test_a_check_switches_nothing_and_still_fails_on_settings_it_cannot_use(tmp_path):
    out = run_apply(tmp_path, conf=CONF + "BLOCK_QUIC=Yes\n", args=("--check",), preset={FORWARDING: "1"})
    assert out.returncode != 0 and nft_changes(tmp_path) == []
    assert switch(tmp_path, FORWARDING) == "1" and "no filter is loaded" not in out.stderr


def test_the_script_has_one_exit_trap():
    """A second `trap ... EXIT` replaces the first without a word: (probe) the confirmation's abort mark
    is left by the same handler that fails closed."""
    assert re.findall(r"^\s*trap .*\bEXIT\b.*$", APPLY, re.M) == ["trap on_exit EXIT"]
    handler = APPLY[APPLY.index("on_exit() {") : APPLY.index("trap on_exit EXIT")]
    assert 'touch "$CONFIRM_DIR/abort"' in handler and "tv_port_dark" in handler


@pytest.mark.parametrize("kernel_has_ipv6", [True, False])
def test_a_kernel_without_ipv6_still_gets_its_filter(tmp_path, kernel_has_ipv6):
    """procps' sysctl fails on a key it cannot stat. On a kernel started with ipv6.disable=1 the write of
    disable_ipv6 stopped every apply before the load, and the TV stayed dark for good. Where the switch
    exists it is still set."""
    proc = PROC if kernel_has_ipv6 else tuple(key for key in PROC if key != V6_SWITCH)
    out = run_apply(tmp_path, proc=proc)
    assert out.returncode == 0, out.stderr
    assert switch(tmp_path, FORWARDING) == "1"
    assert not kernel_has_ipv6 or switch(tmp_path, V6_SWITCH) == "1"
