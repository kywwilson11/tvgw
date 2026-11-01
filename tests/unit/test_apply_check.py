"""`tvgw-apply --check` against the stub commands of test_apply.py: it renders and checks, and nothing else.

The check is what tests/virtual runs on every ruleset variant, and it may be run on the live gateway by
hand, so the property that matters most is the negative one: with the flag, no sysctl is written, no
table is loaded or deleted, no route is touched and nothing is published under /run/tvgw. Whether nft
accepts the rendered text is the virtual suite's question (it needs a kernel); what the script hands
`nft -c` and what it leaves alone is checked here."""

import os
import shutil
import subprocess

import pytest
from test_apply import APPLY, CONF, PROC, STUBS

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")

# the stub nft of test_apply.py, which also answers the check: a `-c -f -` script is kept in its own
# numbered file and refused when it holds REFUSE (an environment variable, empty by default)
CHECK_NFT = STUBS["nft"].replace(
    'case "$*" in\n',
    'case "$*" in\n"-c -f -") n=$(ls "$STUB_DIR" | grep -c \'^check\\.\'); cat >"$STUB_DIR/check.$n"\n'
    '\t[ -z "${REFUSE:-}" ] || ! grep -q "$REFUSE" "$STUB_DIR/check.$n" || exit 1 ;;\n',
    1,
)


def run_check(
    tmp_path, conf: str = CONF, args: tuple[str, ...] = ("--check",), refuse: str = ""
) -> subprocess.CompletedProcess:
    """tvgw-apply with its absolute paths moved under tmp_path, as test_apply.run_apply does, plus args."""
    for d in ("bin", "stub", "etc/tvgw", "state", "run/lock"):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    for name, body in {**STUBS, "nft": CHECK_NFT}.items():
        (tmp_path / "bin" / name).write_text(body, encoding="utf-8")
        (tmp_path / "bin" / name).chmod(0o755)
    for key in PROC:
        (tmp_path / "proc" / "sys" / key).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "proc" / "sys" / key).write_text("0\n", encoding="utf-8")
    (tmp_path / "etc" / "tvgw" / "tvgw.conf").write_text(conf, encoding="utf-8")
    script = (
        APPLY.replace("/etc/tvgw/", f"{tmp_path}/etc/tvgw/")
        .replace("/var/lib/tvgw", f"{tmp_path}/state")
        .replace("/run/", f"{tmp_path}/run/")
        .replace("/proc/sys/", f"{tmp_path}/proc/sys/")
    )
    (tmp_path / "tvgw-apply").write_text(script, encoding="utf-8")
    env = {
        "PATH": f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}",
        "STUB_DIR": str(tmp_path / "stub"),
        "FAKE_PROC": str(tmp_path / "proc"),
        "REFUSE": refuse,
    }
    return subprocess.run(
        ["bash", str(tmp_path / "tvgw-apply"), *args],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def nft_calls(tmp_path) -> list[str]:
    calls = tmp_path / "stub" / "nft.calls"
    return calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []


def checked(tmp_path) -> list[str]:
    """The scripts handed to `nft -c`, in order."""
    files = sorted((tmp_path / "stub").glob("check.*"), key=lambda p: int(p.suffix[1:]))
    return [p.read_text(encoding="utf-8") for p in files]


def test_the_check_hands_every_load_to_nft_c_and_prints_it(tmp_path):
    out = run_check(tmp_path)
    assert out.returncode == 0, out.stderr
    scripts = checked(tmp_path)
    assert [s.splitlines()[0] for s in scripts] == [
        "table inet tvgw",
        "table netdev tvgw_l2",
        "add table inet tvgw_gate",
    ]
    # stdout is the three scripts, one after the other: a file nft -c -f can read on its own
    assert out.stdout == "".join(scripts)
    assert "tvgw: applied" not in out.stdout + out.stderr


def test_the_check_changes_nothing(tmp_path):
    """No load, delete or listing reaches nft; no sysctl, route or rule; nothing under /run/tvgw."""
    out = run_check(tmp_path, conf=CONF + "DNSGATE=off\n")
    assert out.returncode == 0, out.stderr
    assert set(nft_calls(tmp_path)) == {"-c -f -"}  # not even the gate's `delete table`
    assert not (tmp_path / "stub" / "ip.calls").exists()
    assert {(tmp_path / "proc" / "sys" / key).read_text(encoding="utf-8") for key in PROC} == {"0\n"}
    assert not (tmp_path / "run" / "tvgw").exists()
    assert len(checked(tmp_path)) == 2  # DNSGATE=off renders no gate table


def test_the_check_renders_the_switches_the_conf_names(tmp_path):
    conf = "UPLINK=vpn\nBLOCK_QUIC=no\nSTRICT_PORTS=yes\n"
    assert run_check(tmp_path, conf=conf).returncode == 0
    inet = checked(tmp_path)[0]
    assert 'oifname != "tun0" counter drop' in inet and "tunnel MTU" in inet
    assert "undo PIA routed-packet tag" not in inet
    assert "QUIC: force TCP+TLS" not in inet
    assert "STRICT_PORTS: only web, NTP and DNS" in inet


def test_a_ruleset_nft_refuses_fails_the_check_and_nothing_follows(tmp_path):
    out = run_check(tmp_path, refuse="table inet tvgw {")
    assert out.returncode == 1
    assert len(checked(tmp_path)) == 1  # set -e: the l2 and gate tables are never rendered
    assert not (tmp_path / "run" / "tvgw").exists()


def test_a_refused_side_table_fails_the_check_though_an_apply_would_carry_on(tmp_path):
    """An apply tolerates a netdev table that does not load (eth0 down) so the TV is not kept dark;
    the check exists to find exactly that kind of error before a deploy, so it says so in its status."""
    out = run_check(tmp_path, refuse="table netdev tvgw_l2")
    assert out.returncode == 1
    assert len(checked(tmp_path)) == 3  # the gate was still rendered and checked
    assert "netdev IPv6 guard not loaded" in out.stderr


def test_the_check_refuses_a_conf_the_apply_refuses(tmp_path):
    out = run_check(tmp_path, conf=CONF + "DNSGATE=enforce\n")
    assert out.returncode == 1 and "DNSGATE must be off or count" in out.stderr
    assert nft_calls(tmp_path) == []


def test_without_the_flag_the_apply_still_loads_and_never_checks(tmp_path):
    for args in ((), ("--checks",)):  # only the exact flag selects the check
        out = run_check(tmp_path, args=args)
        assert out.returncode == 0, out.stderr
        assert "-c -f -" not in nft_calls(tmp_path)
        assert "tvgw: applied (uplink=direct via wlan0" in out.stdout
        assert (tmp_path / "run" / "tvgw" / "ruleset.applied").exists()
        assert (tmp_path / "run" / "tvgw" / "counters.before-apply").exists()
