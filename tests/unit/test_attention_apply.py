"""(attention) tvgw-apply's attention block (design decision 69), against the stub commands of test_apply.py,
and the units and install steps around it.

What the kernel makes of the rules (the dead-man entries expiring, a connection counted once, the refuse
copy refusing) is the namespace tier's to say (tests/virtual/test_virtual_attention.py). Here: the table
stands only where the live reading runs; it counts and never refuses; `refuse` is refused on a live
gateway with a line saying why; a copy of the script with ATTENTION_REFUSE_SUPPORTED=yes refuses in the
screen-saver and input states alone, after each count and without its tuple test; and nothing about it
can stop an apply."""

import re
import shutil
import subprocess

import pytest
import test_apply
from conftest import ROOT
from test_apply import CONF, run_apply, scripts
from test_apply_check import checked, run_check

from tvgw import attention, config, verify

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="tvgw-apply is a bash script")

APPLY = test_apply.APPLY
LIVE = CONF + "LIVE_READING=on\n"
SUPPORTED = APPLY.replace("\nATTENTION_REFUSE_SUPPORTED=no\n", "\nATTENTION_REFUSE_SUPPORTED=yes\n", 1)
REFUSE_LINE = (
    "ATTENTION_WALL=refuse is not supported on a live gateway yet (design decision 69 says what it lacks)"
)


def attention_load(tmp_path) -> str | None:
    found = [s for s in scripts(tmp_path) if s.startswith("add table inet tvgw_attn\n")]
    assert len(found) <= 1
    return found[0] if found else None


def rules(load: str) -> list[str]:
    return [ln for ln in load.splitlines() if ln.startswith("add rule inet tvgw_attn forward ")]


def nft_calls(tmp_path) -> list[str]:
    return (tmp_path / "stub" / "nft.calls").read_text(encoding="utf-8").splitlines()


def test_the_script_says_no_to_refuse_and_its_copy_is_the_only_change():
    assert APPLY.count("\nATTENTION_REFUSE_SUPPORTED=no\n") == 1
    assert SUPPORTED != APPLY and SUPPORTED.replace("SUPPORTED=yes", "SUPPORTED=no", 1) == APPLY


def test_where_the_live_reading_is_off_no_table_stands_and_an_old_one_goes(tmp_path):
    out = run_apply(tmp_path)
    assert out.returncode == 0, out.stderr
    assert attention_load(tmp_path) is None
    assert "delete table inet tvgw_attn" in nft_calls(tmp_path)


@pytest.mark.parametrize("extra", ["ATTENTION_WALL=off\n", "PROFILE=generic-tv\n", "PROFILE=samsung-tizen\n"])
def test_off_or_another_profile_loads_nothing_even_with_the_live_reading_on(tmp_path, extra):
    out = run_apply(tmp_path, conf=LIVE + extra)
    assert out.returncode == 0, out.stderr
    assert attention_load(tmp_path) is None and "delete table inet tvgw_attn" in nft_calls(tmp_path)


def test_the_count_keeps_its_sets_across_applies_and_counts_three_states_once_per_connection(tmp_path):
    out = run_apply(tmp_path, conf=LIVE)
    assert out.returncode == 0, out.stderr
    load = attention_load(tmp_path)
    assert load is not None and "delete table" not in load and "\ntable inet tvgw_attn {" not in load
    sets = re.findall(r"^add set inet tvgw_attn (\S+) \{ ([^}]*) \}$", load, re.M)
    assert dict(sets) == {
        "platform4": "type ipv4_addr; flags timeout; size 65536;",
        **{n: "type ipv4_addr; flags timeout; size 8;" for n in attention.STATE_SETS.values()},
        "conn4": "type ipv4_addr . inet_proto . inet_service . inet_service; flags dynamic, timeout; timeout 2m;"
        " size 65536;",
        **{
            n: "type ipv4_addr . inet_proto . inet_service . inet_service; flags dynamic, timeout; timeout 3h;"
            " size 4096;"
            for n in attention.SAMPLE_SETS.values()
        },
    }
    assert (
        "add chain inet tvgw_attn forward { type filter hook forward priority filter + 15; policy accept; }"
        in load
    )
    assert "flush chain inet tvgw_attn forward" in load
    found = rules(load)
    assert (
        found[0]
        == 'add rule inet tvgw_attn forward iifname "eth0" ip daddr 156.147.69.32 tcp dport 8080 accept'
    )
    assert len(found) == 4
    for line, state in zip(found[1:], attention.COUNTED, strict=True):
        assert line.endswith(f'comment "{attention.RULES[state]}"')
        assert (
            f'iifname "eth0" ip saddr @{state}4 ct state new meta l4proto {{ tcp, udp }} th dport != 123'
            in line
        )
        assert "ip daddr != 10.10.10.1 ip daddr != @platform4" in line
        assert " != @conn4 add @conn4 { ip daddr . meta l4proto . th sport . th dport } counter add" in line
        assert (
            f" counter add @{state}_seen4 {{ ip daddr . meta l4proto . th sport . th dport }} comment" in line
        )
    for word in ("reject", "drop", "queue", "@app4"):
        assert word not in load  # it counts; it can refuse nothing, and nothing counts the app state yet
    used = (tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
    assert "LIVE_READING=on\nATTENTION_WALL=count\n" in used


def test_refuse_on_a_live_gateway_says_why_and_counts_as_count(tmp_path):
    out = run_apply(tmp_path, conf=LIVE + "ATTENTION_WALL=refuse\n")
    assert out.returncode == 0, out.stderr
    assert REFUSE_LINE in out.stderr and "refuse nothing" in out.stderr
    load = attention_load(tmp_path)
    assert load is not None and "reject" not in load and len(rules(load)) == 4
    # recorded as the conf says it, so verify does not call the conf unapplied for ever
    used = (tmp_path / "run" / "tvgw" / "settings.applied").read_text(encoding="utf-8")
    assert "ATTENTION_WALL=refuse\n" in used


def test_the_copy_that_supports_refuse_refuses_in_the_screen_saver_and_input_states_alone(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(test_apply, "APPLY", SUPPORTED)
    out = run_apply(tmp_path, conf=LIVE + "ATTENTION_WALL=refuse\n")
    assert out.returncode == 0, out.stderr
    assert REFUSE_LINE not in out.stderr
    found = rules(attention_load(tmp_path))
    refusing = [ln for ln in found if "reject" in ln]
    assert [re.search(r"@(\w+)4 ", ln).group(1) for ln in refusing] == ["idle", "input"]  # never live TV
    for line in refusing:
        # after its state's count, with no counter, no tuple test (a retransmission is refused again) and the
        # same essentials, the clock and the gateway let through
        before = found[found.index(line) - 1]
        assert before.endswith(f'comment "{attention.RULES[line.split("@")[1].split("4 ")[0]]}"')
        assert line.endswith("reject with icmpx admin-prohibited") and "counter" not in line
        assert "@conn4" not in line and "ip daddr != @platform4" in line and "th dport != 123" in line
    # count, on the same copy, refuses nothing
    monkeypatch.setattr(test_apply, "APPLY", SUPPORTED)
    again = run_apply(tmp_path / "count", conf=LIVE)
    assert again.returncode == 0 and "reject" not in attention_load(tmp_path / "count")


def listed(sets: dict[str, str]) -> str:
    """The stub nft, answering `-t list set inet tvgw_attn <name>` with the given listing for each name."""
    arms = "".join(
        f"\"-t list set inet tvgw_attn {name}\") printf %s '{body}' ;;\n" for name, body in sets.items()
    )
    stub = test_apply.STUBS["nft"].replace('case "$*" in\n', 'case "$*" in\n' + arms, 1)
    assert stub != test_apply.STUBS["nft"]
    return stub


def set_listing(
    name: str, type_: str, size: int, flags: str, timeout: str = "", holds: int | None = None
) -> str:
    """A set as `nft -t list set` prints it; with `holds`, as nft 1.1.6 does, the count after the size."""
    counted = "" if holds is None else f"\t# count {holds}"
    lines = [f"\t\ttype {type_}", f"\t\tsize {size}{counted}", f"\t\tflags {flags}"]
    if timeout:
        lines.append(f"\t\ttimeout {timeout}")
    return "table inet tvgw_attn {\n\tset " + name + " {\n" + "\n".join(lines) + "\n\t}\n}\n"


TUPLE = "ipv4_addr . inet_proto . inet_service . inet_service"
AS_WRITTEN = {
    "platform4": set_listing("platform4", "ipv4_addr", 65536, "timeout"),
    **{n: set_listing(n, "ipv4_addr", 8, "timeout") for n in attention.STATE_SETS.values()},
    "conn4": set_listing("conn4", TUPLE, 65536, "dynamic,timeout", "2m"),
    **{n: set_listing(n, TUPLE, 4096, "dynamic,timeout", "3h") for n in attention.SAMPLE_SETS.values()},
}


COUNTED = AS_WRITTEN | {
    "platform4": set_listing("platform4", "ipv4_addr", 65536, "timeout", holds=41),
    "conn4": set_listing("conn4", TUPLE, 65536, "dynamic,timeout", "2m", holds=0),
}


@pytest.mark.parametrize(
    "sets", [AS_WRITTEN, COUNTED], ids=["as nft 1.1 lists them", "with what each holds, as 1.1.6 does"]
)
def test_a_table_whose_sets_are_as_written_is_kept_with_its_essentials_and_samples(tmp_path, sets):
    out = run_apply(tmp_path, conf=LIVE, stubs={"nft": listed(sets)})
    assert out.returncode == 0, out.stderr
    assert "delete table inet tvgw_attn" not in nft_calls(tmp_path) and "other properties" not in out.stderr
    assert sum(1 for c in nft_calls(tmp_path) if c.startswith("-t list set inet tvgw_attn ")) == len(
        AS_WRITTEN
    )
    assert len([s for s in scripts(tmp_path) if s.startswith("add table inet tvgw_attn")]) == 1


@pytest.mark.parametrize(
    ("name", "listing"),
    [
        ("idle_seen4", set_listing("idle_seen4", TUPLE, 4096, "dynamic,timeout", "1h")),  # another lifetime
        ("platform4", set_listing("platform4", "ipv4_addr", 1024, "timeout")),  # another size
        ("idle4", set_listing("idle4", "ipv4_addr", 8, "interval")),  # other flags
        ("conn4", set_listing("conn4", "ipv4_addr", 65536, "dynamic,timeout", "2m")),  # another type
    ],
)
def test_a_set_of_other_properties_has_the_table_made_again_before_the_load_and_says_so(
    tmp_path, name, listing
):
    out = run_apply(tmp_path, conf=LIVE, stubs={"nft": listed({**AS_WRITTEN, name: listing})})
    assert out.returncode == 0, out.stderr
    assert "inet tvgw_attn held a set of other properties; it is made again" in out.stderr
    calls = nft_calls(tmp_path)
    loads = [i for i, c in enumerate(calls) if c == "-f -"]
    attn = [s for s in scripts(tmp_path) if s.startswith("add table inet tvgw_attn")]
    assert len(attn) == 1  # deleted, then one load
    assert calls.index("delete table inet tvgw_attn") < loads[-1]
    assert "tvgw: applied (" in out.stdout


def test_a_load_that_fails_otherwise_only_warns_and_keeps_the_table(tmp_path):
    """A passing error (the kernel busy, a full transaction) must not throw away the essentials and the
    samples the table holds: nothing is deleted, the apply goes on, and the next apply tries again."""
    refusing = listed(AS_WRITTEN).replace(
        '"-f -") n=$(ls "$STUB_DIR" | grep -c \'^nft-script\\.\'); cat >"$STUB_DIR/nft-script.$n" ;;',
        '"-f -") n=$(ls "$STUB_DIR" | grep -c \'^nft-script\\.\'); cat >"$STUB_DIR/nft-script.$n"\n'
        '\tif head -n 1 "$STUB_DIR/nft-script.$n" | grep -q tvgw_attn; then exit 1; fi ;;',
        1,
    )
    out = run_apply(tmp_path, conf=LIVE, stubs={"nft": refusing})
    assert out.returncode == 0, out.stderr
    assert (
        "attention count table not loaded; it stays as it was, and the next apply tries again" in out.stderr
    )
    assert "delete table inet tvgw_attn" not in nft_calls(tmp_path)
    assert (tmp_path / "proc" / "sys" / "net" / "ipv4" / "conf" / "eth0" / "forwarding").read_text() == "1\n"


@pytest.mark.parametrize(
    ("key", "value"), [("LIVE_READING", "On"), ("LIVE_READING", "yes"), ("ATTENTION_WALL", "enforce")]
)
def test_a_near_miss_stops_the_apply_before_anything_is_loaded(tmp_path, key, value):
    out = run_apply(tmp_path, conf=CONF + f"{key}={value}\n")
    assert out.returncode == 1 and f"{key} must be" in out.stderr
    assert scripts(tmp_path) == []
    with pytest.raises(ValueError, match=key):
        config.check_conf(CONF + f"{key}={value}\n")


def test_the_check_renders_the_table_and_never_falls_back(tmp_path):
    out = run_check(tmp_path, conf=LIVE)
    assert out.returncode == 0, out.stderr
    found = [s for s in checked(tmp_path) if s.startswith("add table inet tvgw_attn")]
    assert len(found) == 1 and "add table inet tvgw_attn\n" in out.stdout
    refused = run_check(tmp_path / "refused", conf=LIVE, refuse="tvgw_attn")
    assert refused.returncode == 1
    assert len([s for s in checked(tmp_path / "refused") if s.startswith("add table inet tvgw_attn")]) == 1


def test_verify_compares_both_keys_with_what_the_apply_used():
    assert {"LIVE_READING", "ATTENTION_WALL"} <= set(verify.APPLY_KEYS)
    used = verify.apply_settings("LIVE_READING=on\n")
    assert used["LIVE_READING"] == "on" and used["ATTENTION_WALL"] == "count"


# ---- the units and the install ------------------------------------------------------------------------
UNIT = (ROOT / "deploy" / "systemd" / "tvgw-attention.service").read_text(encoding="utf-8")
LIVE_UNIT = (ROOT / "deploy" / "systemd" / "tvgw-tvlive.service").read_text(encoding="utf-8")
INSTALL = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")


def unit_values(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            k, v = line.split("=", 1)
            out.setdefault(k, []).append(v)
    return out


def test_the_holder_holds_one_capability_and_can_reach_no_address():
    u = unit_values(UNIT)
    assert u["CapabilityBoundingSet"] == ["CAP_NET_ADMIN"] and u["AmbientCapabilities"] == ["CAP_NET_ADMIN"]
    assert u["RestrictAddressFamilies"] == ["AF_NETLINK AF_UNIX"] and u["IPAddressDeny"] == ["any"]
    assert u["ProtectSystem"] == ["strict"] and u["NoNewPrivileges"] == ["yes"]
    assert u["SystemCallFilter"] == ["@system-service"] and u["SystemCallErrorNumber"] == ["EPERM"]
    assert u["PrivateDevices"] == ["yes"] and u["RestrictNamespaces"] == ["yes"]
    assert u["RuntimeDirectory"] == ["tvgw-attention"] and u["RuntimeDirectoryMode"] == ["0750"]
    assert u["Type"] == ["notify"] and u["WatchdogSignal"] == ["SIGKILL"]
    assert u["ExecStart"] == ["/usr/local/bin/tvgw attention-hold"]
    assert "ReadWritePaths" not in u  # it writes nothing on the card
    assert "Requires" not in u and "BindsTo" not in u  # bound to neither the firewall nor the live reading


def test_the_live_reading_writes_its_word_in_memory_and_still_holds_no_capability():
    u = unit_values(LIVE_UNIT)
    assert u["RuntimeDirectory"] == ["tvgw-tvlive"] and u["RuntimeDirectoryMode"] == ["0700"]
    assert u["CapabilityBoundingSet"] == [""] and u["RestrictAddressFamilies"] == ["AF_INET AF_UNIX"]
    assert attention.STATE_FILE == "/run/tvgw-tvlive/attention"
    assert attention.STATUS == "/run/tvgw-attention/status.json"


@pytest.mark.parametrize(
    ("conf", "rc"),
    [
        (None, 1),
        ("", 1),
        ("LIVE_READING=on\n", 0),
        ("LIVE_READING=on\nATTENTION_WALL=refuse\n", 0),
        ("LIVE_READING=on\nATTENTION_WALL=off\n", 1),
        ("LIVE_READING=on\nPROFILE=generic-tv\n", 1),
        ("LIVE_READING=off\n", 1),
        ("LIVE_READING=on\nATTENTION_WALL=Count\n", 255),
    ],
)
def test_the_units_condition_reads_the_settings_as_the_holder_does(tmp_path, conf, rc):
    cond = unit_values(UNIT)["ExecCondition"][0]
    script = cond.split("/bin/sh -c '", 1)[1].rsplit("'", 1)[0].replace("$$", "$")
    path = tmp_path / "tvgw.conf"
    if conf is not None:
        path.write_text(conf, encoding="utf-8")
    script = script.replace("/etc/tvgw/tvgw.conf", str(path))
    assert subprocess.run(["sh", "-c", script], capture_output=True).returncode == rc


def test_the_install_enables_the_holder_and_restarts_it_when_the_settings_or_the_package_change():
    enable = next(ln for ln in INSTALL.splitlines() if ln.startswith("systemctl enable --now tvgw-flowlog"))
    assert "tvgw-attention.service" in enable.split()
    assert "| tvgw-attention)" in INSTALL
    assert "\nrestart_changed tvgw-attention " in INSTALL
    prerm = (ROOT / "packaging" / "scripts" / "prerm").read_text(encoding="utf-8")
    assert "tvgw-attention.service" in prerm
